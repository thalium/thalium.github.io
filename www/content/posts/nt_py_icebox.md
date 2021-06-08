---
title: "NT objects access tracing"
date: 2021-06-07T12:00:00+01:00
draft: false
author: "Arnaud Gatignol"
twitter: "_anyfun"
---

# Draw me a map

As homework during the lockdown, I wanted to automate the attack surface analysis of a target on **Windows**. The main objective was to construct a view of a software architecture to highlight the attack surface (whether remote or local).

The software architecture can be composed of several elements:

* processes
* privileges
* ipc
* etc

Usually, software architecture analysis is done with tools that give a view at a specific time (`ProcessHacker`, `WinObjEx`, etc). However, the different components of the software architecture might be invoked dynamically and temporarily on certain conditions. Monitoring tools such as `ProcMon` can help in this context but these involve manual operations.

Thus, the changes in the software architecture should be considered in order to obtain an exhaustive view of it.

Enter [Icebox](https://github.com/thalium/icebox), a VMI (Virtual Machine Introspection) framework, which gives the ability to **monitor** a virtual machine and its overlying operating system.
Nonetheless, basic support for Windows needs to be implemented before we can consider constructing a view of the software architecture and its attack surface.

Especially, with primitive support for the `NT Object namespace`, we will be able to collect essential information to construct the attack surface.
The output of this support will be, at first, a basic textual log of collected information.

Finally, with VMI, code execution inside the virtual machine is not an option. Thus, we will have to reimplement Windows kernel functions to mimic their behavior.
Projects such as [Rekall](https://github.com/google/rekall) and [Volatility](https://github.com/volatilityfoundation/volatility) are good open source entry points. I also tend to intensively use the kernel itself (`ntoskrnl.exe`) or even WinDBG to validate my assumptions.

This blogpost does not intend to present new Windows concepts (everything below has already been documented). However, it shows a practical/playful way to navigate inside the Windows kernel with Icebox.

**Disclaimer: the implementation given below has no intention to fully support Windows with all its versions and all their specificities.**

**Disclaimer 2: I worked on this subject without publication in mind. I failed to record every resource I used and some references might be missing. Feel free to let me know if you spot anything wrong.**

# Processes

With Icebox, there are two ways to monitor processes:

* list living processes
* observe the creation of processes

These two methods have been documented in a [previous blogpost](/blog/posts/getting_started/):

```python
import icebox

vm = icebox.attach("win10")

# list current processes
for proc in vm.processes():
    print("%d: %s" % (proc.pid(), proc.name()))

def on_create(proc):
    print("+ %d: %s" % (proc.pid(), proc.name()))

# break on process creation
with vm.processes.break_on_create(on_create):
    vm.exec()
```

Obviously, all of the output of these methods won't necessarily be related to our software, some of these processes need to be filtered out.
A good criterion to filter the processes is the image file name location (e.g. in the software installation folder).

# Windows IPC

From the established list of processes, it is possible to monitor all interactions between them and other Windows objects. The focal point of these interactions is the creation by a process of a `HANDLE` to another Windows object.

Some of the Windows objects accessed could be used by the target software as a way to receive data. Analyzing these objects and their `security descriptor` will give a representation of the prime attack surface.

## Break at some point

The `HANDLE` creation is done by Windows through the kernel function `nt!ObpCreateHandle`. By breaking onto this function, it is possible to monitor all accesses to the objects by the software processes.

The prototype of this function is given below:

```c
NTSTATUS
ObpCreateHandle(
  IN  OB_OPEN_REASON OpenReason,
  IN  PVOID Object,
  IN  POBJECT_TYPE ExpectedObjectType OPTIONAL,
  IN  PACCESS_STATE AccessState,
  IN  ULONG ObjectPointerBias OPTIONAL,
  IN  ULONG Attributes,
  IN  POBP_LOOKUP_CONTEXT LookupContext,
  IN  KPROCESSOR_MODE AccessMode,
  OUT PVOID *ReferencedNewObject OPTIONAL,
  OUT PHANDLE Handle
  );
```

The parameter of interest is `PVOID Object` which is a pointer to the body of the object.

In order to break onto this function and obtain said pointer through Icebox, we can use the following snippet:

```python
import icebox
from nt_types import *

# specify the targeted VM
vm = icebox.attach("win10")
proc = vm.processes.current()

# get the address of the given symbol
addr = proc.symbols.address("nt!ObpCreateHandle")

# breakpoint callback
def on_break():
    p = vm.processes.current()
    p.symbols.load_modules()

    # access the argument stored in rdx
    _object = nt_Object(p, vm.registers.rdx)

while True:
    # break on the address of nt!ObpCreateHandle and execute the callback on_break
    with vm.break_on(addr, on_break):
        vm.exec()

```

At this point, the object has an opaque structure, it might be needed to support the specificities of each object type. Indeed, the `PVOID` pointer will be used as specific type pointer by the NT Object Manager:

* `nt!_FILE_OBJECT`
* `nt!_SECTION_OBJECT`
* `nt!_ALPC_PORT`
* etc

To go further, we need to obtain generic information about the object. This has been done through the implementation of the `nt_Object` class.

## Generic object handling

In Windows, an `nt object` is **roughly** composed of two parts:

* an object header containing metadata such as: `object type`, `security descriptor`, `creator information`, `object name`, etc
* an object body containing all the specific information of the `nt object`

In order to access these data through the opaque nt object pointer we have, it is required to implement the object specifities through Icebox.

Here is an example of the `nt_Object` class [implementation](https://github.com/agatignol/NtPy/blob/master/handle_tracer/nt_types.py#L531):

```python
class nt_Object():
    def __init__(self, proc, p_object):
        self.object = p_object

        # obtain a pointer to the header of the object
        self.object_header = self.__get_object_header(proc)

        # obtain the info mask in order to obtain metadata on the object
        self.object_header_info_mask = self.__get_object_header_info_mask(proc)

        # obtain the pointer to the security descriptor of the object
        self.sd = self.__get_object_sd(proc)

        # obtain the object type
        self.object_type = self.__get_object_type(proc)

        # obtain a pointer to the body of the object
        self.object_body = self.__get_object_body(proc)
```

In order to get a better handling of the object body, it is necessary to identify the object type.

To obtain the object type, the Windows kernel uses the `nt!ObGetObjectType` function. Below, one implementation of this function is given.
This implementation relies on two functions:

* an accesser to the encoded object type: `__get_object_type`
* a decoder to retrieve the real object type: `__get_type_index`

```python
    def __get_type_index(self, proc, ObHeaderCookie):

        offset = get_symbol_offset(proc, "nt!_OBJECT_HEADER", "TypeIndex")
        typeindex = read_byte(proc, self.object_header + offset)[0]

        cookie = read_byte(proc, ObHeaderCookie)[0]
        addr_lsb = get_n_byte(self.object_header, 1)

        # use the cookie to get the real index
        index = typeindex ^ cookie ^ int(addr_lsb, 16)

        return index

   def __get_object_type(self, proc):
       # nt!ObGetObjectType

       if self.object_header == 0:
           return 0

       # array of object type
       ObTypeIndexTable = proc.symbols.address("nt!ObTypeIndexTable")

       # object type protection cookie
       ObHeaderCookie = proc.symbols.address("nt!ObHeaderCookie")

       index = self.__get_type_index(proc, ObHeaderCookie)
       a_object_type = ObTypeIndexTable + (index * 8)
       object_type = read_uint64(proc, a_object_type)

       o_name = get_symbol_offset(proc, "nt!_OBJECT_TYPE", "Name")
       name_string = object_type + o_name
       object_type_name = get_unicode_string(proc, name_string)

       return object_type_name
```

Apart from the kernel itself, more details are given in the following blogpost to retrieve the object type:

* https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a

To summarize, we are now able to get three properties regarding a requested `HANDLE`:

* the object **type**
* the object **header**
* the object **body**

Once the object type is determined, it is possible to gather object type-specific information through type-specific handlers.

For instance, the `nt_Process` class, used to represent `nt!_EPROCESS`, implements the `__get_mitigations` method to gather its `MitigationFlagsValues`.

```python
import icebox
import argparse
from utils import *
from nt_types import nt_Process


MITIGATIONS = {
    0x00000001: "ControlFlowGuardEnabled",
    0x00000002: "ControlFlowGuardExportSuppressionEnabled",
    0x00000004: "ControlFlowGuardStrict",
    0x00000008: "DisallowStrippedImages",
    0x00000010: "ForceRelocateImages",
    0x00000020: "HighEntropyASLREnabled",
    0x00000040: "StackRandomizationDisabled",
    0x00000080: "ExtensionPointDisable",
    0x00000100: "DisableDynamicCode",
    0x00000200: "DisableDynamicCodeAllowOptOut",
    0x00000400: "DisableDynamicCodeAllowRemoteDowngrade",
    0x00000800: "AuditDisableDynamicCode",
    0x00001000: "DisallowWin32kSystemCalls",
    0x00002000: "AuditDisallowWin32kSystemCalls",
    0x00004000: "EnableFilteredWin32kAPIs",
    0x00008000: "AuditFilteredWin32kAPIs",
    0x00010000: "DisableNonSystemFonts",
    0x00020000: "AuditNonSystemFontLoading",
    0x00040000: "PreferSystem32Images",
    0x00080000: "ProhibitRemoteImageMap",
    0x00100000: "AuditProhibitRemoteImageMap",
    0x00200000: "ProhibitLowILImageMap",
    0x00400000: "AuditProhibitLowILImageMap",
    0x00800000: "SignatureMitigationOptIn",
    0x01000000: "AuditBlockNonMicrosoftBinaries",
    0x02000000: "AuditBlockNonMicrosoftBinariesAllowStore",
    0x04000000: "LoaderIntegrityContinuityEnabled",
    0x08000000: "AuditLoaderIntegrityContinuity",
    0x10000000: "EnableModuleTamperingProtection",
    0x20000000: "EnableModuleTamperingProtectionNoInherit"
}


class nt_Process():
    def __init__(self, proc, body):
        self.process = body
        self.name = self.__get_process_name(proc)
        self.pid = self.__get_pid(proc)
        self.token = self.__get_token(proc)
        self.parent = self.__get_parent(proc)
        self.mitigations = self.__get_mitigations(proc)

        self.il = ""
        if self.token != 0:
            self.il = self.token.get_il()

    def __str__(self):
        info = (
            f"Process: {self.name}",
            f"ParentId: {self.parent}"
        )
        if self.mitigations:
            info += "Mitigations:",
            for mitigation in self.mitigations:
                info += f"\t{mitigation}"

        info += f"Integrity level: {self.il}"
        return os.linesep.join(info)

    def get_name(self):
        return self.name

    def get_pid(self):
        return self.pid

    def get_mitigations(self):
        return self.mitigations

    def get_parent_pid(self):
        return self.parent

    def __get_token(self, proc):
        if self.process == 0:
            return 0

        o_token = get_symbol_offset(
            proc, "nt!_EPROCESS", "Token")
        a_token = self.process + o_token

        token = read_uint64(proc, a_token)
        token = token & 0xfffffffffffffff0

        if token == 0:
            return 0

        return nt_Token(proc, token)

    def __get_parent(self, proc):
        if self.process == 0:
            return 0

        o_pid = get_symbol_offset(
            proc, "nt!_EPROCESS", "OwnerProcessId")
        a_pid = self.process + o_pid
        return read_uint64(proc, a_pid)

    def __resolve_mitigations(self, proc, mitigationflag, mitigationflag2):
        mitigations = []
        for k, v in MITIGATIONS.items():
            if k & mitigationflag:
                mitigations.append(v)

        for k, v in MITIGATIONS2.items():
            if k & mitigationflag2:
                mitigations.append(v)

        return mitigations

    def __get_mitigations(self, proc):
        if self.process == 0:
            return 0

        o_flag = get_symbol_offset(
            proc, "nt!_EPROCESS", "MitigationFlags")
        a_flag = self.process + o_flag

        flag_b = proc.memory[a_flag:a_flag + 4]
        flag = unpack_from("<I", flag_b)[0]

        o_flag2 = get_symbol_offset(
            proc, "nt!_EPROCESS", "MitigationFlags2")
        a_flag2 = self.process + o_flag2
        flag2_b = proc.memory[a_flag2:a_flag2 + 4]
        flag2 = unpack_from("<I", flag2_b)[0]
        mitigations = self.__resolve_mitigations(proc, flag, flag2)
        return mitigations

    def __get_pid(self, proc):
        if self.process == 0:
            return 0

        o_pid = get_symbol_offset(
            proc, "nt!_EPROCESS", "UniqueProcessId")
        a_pid = self.process + o_pid
        return read_uint64(proc, a_pid)

    def __get_process_name(self, proc):
        if self.process == 0:
            return 0

        o_name = get_symbol_offset(
            proc, "nt!_EPROCESS", "ImageFileName")
        a_name = self.process + o_name
        return self.__read_process_name(proc, a_name)

    def __read_process_name(self, proc, a_name):
        name = bytearray()
        for i in range(15):
            name += read_byte(proc, a_name + i)
        return name.decode("utf8", "ignore")

vm = icebox.attach("win10")
process = nt_Process(vm.processes.current(), vm.processes.current().native())
print(process)

```

An example output for this would be:

```
Process: svchost.exe (1184)
ParentId: 566
Mitigations:
        ControlFlowGuardEnabled
        HighEntropyASLREnabled
Integrity level: System
```

## Security descriptor and inner structures

The handling of the `object header` gives access to generic information such as `nt!_SECURITY_DESCRIPTOR` and the related `ACL` and `ACE`.

This security information is used to determine whether it is possible to access the object with a given identity.

There will be some cases where the `nt!_SECURITY_DESCRIPTOR` is `NULL`. Usually, this means that anyone can access the object.

> However, this is not true regarding `files`. Indeed, the `nt namespace object` does not manage the security of files on the filesystem.

For most of the object types, the `security descriptor` in the object header is representative.

To get access to it, the Windows kernel uses the `nt!ObGetObjectSecurity` function, which is reimplemented below:

```python
    def __get_object_sd(self, proc):
        # nt!ObGetObjectSecurity

        o_sd = get_symbol_offset(
            proc, "nt!_OBJECT_HEADER", "SecurityDescriptor")
        a_sd = self.object_header + o_sd
        sd = read_uint64(proc, a_sd)

        if sd == 0:
            return 0

        sd = sd & 0xfffffffffffffff0

        return nt_SecurityDescriptor(proc, sd)
```

Here is an example of the `nt_SecurityDescriptor` class implementation:

```python
class nt_SecurityDescriptor():
    def __init__(self, proc, sd):
        self.sd = sd
        self.revision = self.__get_revision(proc)
        self.control = self.__get_control_flags(proc)
        self.dacl = 0
        self.sacl = 0
        if self.control & SE_DACL_PRESENT:
            self.dacl = self.__get_dacl(proc)
        if self.control & SE_SACL_PRESENT:
            self.sacl = self.__get_sacl(proc)

        self.owner_sid = self.__get_owner_sid(proc)
        self.group_sid = self.__get_group_sid(proc)
```

The important member of this class is the `dacl`.

`dacl` identifies the trustees that are allowed or denied access to a securable object.

Both `dacl` and `sacl` are access control list (`ACL`):

* `dacl`: identifies the users and groups that are allowed or denied access
* `sacl`: controls how access is audited

In Windows, the `dacl` is implemented as a list of access control entries (`ACE`).
An `ACE` is a pair of trustee with its access to the targeted securable object.

The [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) describes in further details its ACL mechanisms.

To obtain the `dacl` of a `security descriptor`, an implementation of the kernel function `nt!RtlGetDaclSecurityDescriptor` is required. Below, one possible implementation:

```python
    def __get_dacl(self, proc):
        # nt!RtlGetDaclSecurityDescriptor

        if self.sd == 0:
            return 0

        # only revision 1 is supported
        if self.revision != 1:
            return 0

        o_group = get_symbol_offset(
            proc, "nt!_SECURITY_DESCRIPTOR", "Group")

        group_value = read_uint64(proc, self.sd + o_group)
        group_value = group_value & 0x00000000ffffffff
        dacl = self.sd + group_value

        return nt_Acl(proc, dacl)
```

This `dacl` is then read through the `nt_Acl` class:

```python
class nt_Acl():
    def __init__(self, proc, acl):
        self.acl = acl
        self.revision, sbz, self.acl_size, self.ace_count, sbz2 = self.__get_acl_info(
            proc)
        self.ace_list = self.__get_ace_list(proc)
```

> A good reference to extract information from `ACL` has been the following stackoverflow post:
> * https://stackoverflow.com/questions/34698927/python-get-windows-folder-acl-permissions
> I have reused a good portion of the code given in example.

The list of `ACE` is walked through with the following function, which is a reimplementation of `nt!RtlGetAce`:

```python
    def __get_ace_list(self, proc):
        # nt!RtlGetAce

        ace_list = []

        ace_array = self.acl + proc.symbols.struc("nt!_ACL").size

        if self.ace_count <= 0:
            return ace_list

        offset = 0
        for ace in range(self.ace_count):
            if (ace_array + offset >= self.acl + self.acl_size):
                break

            ace_addr = ace_array + offset
            acestr = proc.memory[ace_addr:ace_addr + 4]
            ace_type, ace_flags, ace_size = unpack_from("<BBH", acestr)

            if (ace_size == 0):
                break

            # documentation: windows_protocols/ms-dtyp (https://docs.microsoft.com/openspecs/windows_protocols/ms-dtyp)

            if (ace_type == 0x00):
                # struct ACCESS_ALLOWED_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            elif (ace_type == 0x01):
                # struct ACCESS_DENIED_ACE_TYPE
                ace_mask = read_uint64(proc, ace_array + 4 + offset)
                ace_mask = ace_mask & 0x00000000ffffffff
                ace_sid = get_sid_string(proc, ace_array + 8 + offset)
            else:
                # ACE Type not handled
                break

            offset = offset + ace_size

            trustee = None
            ace = self.__get_ace(proc, ace_type,
                                 ace_flags, ace_mask, ace_sid, trustee)
            ace_list.append(ace)
        return ace_list
```

Unfortunately, the types `_ACE_HEADER` and `_ACE` are not published in the Windows symbols. The definition used in the implementation of `nt!RtlGetAce` is given below:

```
    # 00000000 _ACE            struc
    # (sizeof=0x8, align=0x4, copyof_2324)
    # 00000000 Header          ACE_HEADER ?
    # 00000004 AccessMask      dd ?
    # 00000008 _ACE            ends

    # 00000000 ACE_HEADER      struc
    # (sizeof=0x4, align=0x2, copyof_2325)
    # 00000000 AceType         db ?
    # 00000001 AceFlags        db ?
    # 00000002 AceSize         dw ?
    # 00000004 ACE_HEADER      ends

    # 00000000 _ACCESS_ALLOWED_ACE struc
    # (sizeof=0xC, align=0x4, copyof_2328)
    # 00000000 Header          ACE_HEADER ?
    # 00000004 Mask            dd ?
    # 00000008 SidStart        dd ?
    # 0000000C _ACCESS_ALLOWED_ACE ends
```

And finally, an `ACE` object is initialized in an `nt_Ace` class. This class will interpret the `AccessMask` and render the `Sid` of the trustee.

As a result, we are now able to get the list of authorized accesses for every object accessed through a `HANDLE` request.

An example of output for this would be:

```
Object: 0xffffd9025e00c060
Object type: Token

DACL:
	S-1-5-18:(DE,RC,WDAC,WO,RD,WD,AD,REA,WEA,X,DC,RA,WA)
	S-1-3-4:(RC)
	S-1-5-80-3635958274-2059881490-2225992882-984577281-633327304:(DE,RC,WDAC,WO,RD,WD,AD,REA,WEA,X,DC,RA,WA)
	S-1-5-32-544:(REA)
SACL:
	S-1-16-16384:(RD)
```

# Privileges

From there, it is possible to construct a complete map of the target software:

* a list of processes
* a list of interactions through nt objects
* the ACL of the nt objects used

The attack surface is almost established. The privileges of the involved processes are not known yet.
Indeed, from an attacker point of view, it is interesting to target processes that have more privileges (e.g. privilege escalation). As a standard user has a `Medium integrity level`, then all processes running with a lower integrity level are not interesting.

To obtain this information, it is required to analyze the token of the processes.

```python

INTEGRITY_LEVEL = {
    0x0000: "Untrusted",
    0x1000: "Low",
    0x2000: "Medium",
    0x3000: "High",
    0x4000: "System"
}

class nt_Token():
    def __init__(self, proc, p_token):
        self.token = p_token
        self.il = self.__get_il(proc)

    def get_il(self):
        return self.il

    def __get_il(self, proc):

        if self.token == 0:
            return 0

        o_sidhash = get_symbol_offset(
            proc, "nt!_TOKEN", "SidHash")
        a_sidhash = self.token + o_sidhash

        if a_sidhash == 0:
            return 0

        count = read_uint64(proc, a_sidhash)

        o_arraysid = get_symbol_offset(
            proc, "nt!_TOKEN", "UserAndGroups")
        a_arraysid = self.token + o_arraysid

        arraysid = read_uint64(proc, a_arraysid)

        size = proc.symbols.struc("nt!_SID_AND_ATTRIBUTES").size

        sid = None
        ptr = arraysid

        if arraysid == 0:
            return 0

        for sid in range(count):

            o_attributes = get_symbol_offset(
                proc, "nt!_SID_AND_ATTRIBUTES", "Attributes")
            a_attributes = ptr + o_attributes
            attributes = read_uint64(proc, a_attributes)
            if attributes & 0x20:  # SE_GROUP_INTEGRITY = 0x00000020L
                o_sid = get_symbol_offset(
                    proc, "nt!_SID_AND_ATTRIBUTES", "Sid")
                a_sid = ptr + o_sid
                sid = read_uint64(proc, a_sid)

                subauthority = get_sid_subauthority(proc, sid)
                for k, v in INTEGRITY_LEVEL.items():
                    if k & subauthority:
                        return v
            ptr += size

        return 0
```

The integrity level of a token can now be obtained and the attack surface is now complete.

Indeed, we can choose the attack surface to analyze with the following criteria:

* accessible surface (ACL)
* object type used to interact
* targeted process privileges (integrity level)

# Showtime: Live Windows

As a demonstration of the tool, here is a sample of the kind of information you can collect on a running Windows:

```
--------------------------------
Process: dwm.exe         (948)
ParentId: 540
Mitigations:
	ControlFlowGuardEnabled
	HighEntropyASLREnabled
Integrity level: System

Object: 0xffffd9025e00c060
Object type: Token
Owner: NT Authority
DACL:
	S-1-5-18:(DE,RC,WDAC,WO,RD,WD,AD,REA,WEA,X,DC,RA,WA)
	S-1-3-4:(RC)
	S-1-5-80-3635958274-2059881490-2225992882-984577281-633327304:(DE,RC,WDAC,WO,RD,WD,AD,REA,WEA,X,DC,RA,WA)
	S-1-5-32-544:(REA)
SACL:
	S-1-16-16384:(RD)

--------------------------------
Process: dwm.exe         (948)
ParentId: 540
Mitigations:
	ControlFlowGuardEnabled
	HighEntropyASLREnabled
Integrity level: System

Object: 0xffff820f667444a0
Object type: File

Security Descriptor: NULL

--------------------------------
Process: dwm.exe         (948)
ParentId: 540
Mitigations:
	ControlFlowGuardEnabled
	HighEntropyASLREnabled
Integrity level: System

Object: 0xffff820f69f442e0
Object type: Event

Security Descriptor: NULL
```

As we can see, the process `dwm.exe` which is running with `SystemIL` has asked access to (in the output order):

* a `token` which has specific `dacl`
* a `file` (`ACL` on files are handled differently)
* an `event` that is accessible to `everyone`

Obviously, it is possible to also get the [callstack](https://github.com/thalium/icebox/blob/2bce97eb589ccbefe8fd1260fef3cb4cb158fb71/src/icebox/icebox_py/examples/getting_started.py#L12) of the handle creation.

The code of this POC is available [here](https://github.com/agatignol/NtPy/tree/master/handle_tracer).

# Further work

At this point, it is possible to imagine several ways to improve the process:

1. store the data in [Neo4j](https://neo4j.com/) to improve the visualization

The textual log output is not optimal to play with. A graph visualization could be a lot more intuitive to observe links between processes and objects.

2. start the reverse of `ntfs.sys` to obtain the ACL on files

`ACL` on files are not stored in the `Object Manager`, it would be interesting to deep dive into `ntfs.sys` to understand how the `ACL` can be accessed through memory if possible.

3. implement a scenario to autoloot vulnerabilities (e.g. based on privileged file operations)

Even if Windows 10 implements hardlink mitigations that reduce the likelihood of privileged file operation vulnerabilities, it would be interesting to correct this kind of [bugs](https://offsec.almond.consulting/intro-to-file-operation-abuse-on-Windows.html).

