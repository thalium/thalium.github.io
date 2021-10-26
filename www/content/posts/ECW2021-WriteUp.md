---
title: "ECW 2021 - WriteUp"
date: 2021-10-25T12:00:01+01:00
draft: false
author: "Thalium team"
tags:
  - CTF
  - Writeup
  - ECW 2021
  - Reverse Engineering
  - Exploitation
---


For the [European Cyber Week](https://www.european-cyber-week.eu/) CTF 2021 Thalium created some challenges in our core competencies: reverse and exploitation. This blog post presents some of the write-ups:
* [Chest (36 solve) - reverse](#chest)
* [FSB as a service (3 solve) - exploitation](#fsb-as-a-service)
* [WYSIWYG (3 solve) - reverse](#wysiwyg)
* Pipe Dream (1 solve) - reverse
  * the author posted his solution on [his personal blog](https://face.0xff.re/posts/ecw-ctf-2021-pipe-dream-writeup/)

Thalium's challenges have been less resolved than others. They were not that difficult, but probably a bit more unexpected. A few additional challenges designed by Thalium are:
<!--more-->
* EMU (3 solve) - reverse
* Hospital simulator (3 solve) - exploitation

As a reminder, Thalium - part of THALES group - is a cybersecurity team dedicated to vulnerability research and development of Red Team-type tools. The team is located in Rennes and we are actively recruiting experienced or high potential profiles in reverse, forensics, and software development. Spoiler: we also offer internships, see [below](#internships-2022).

## Chest <!-- omit in toc -->

The provided file [chest.hex](/posts/binaries/ECW_2021/chest.hex) is in [Intel HEX format](https://www.intel.com/content/www/us/en/support/programmable/articles/000076770.html).

```console
$ cat chest.hex
:100000000C9434000C9449000C9449000C94490061
:100010000C9449000C9449000C9449000C9449003C
:100020000C9449000C9449000C9449000C9449002C
:100030000C9449000C9449000C9449000C9449001C
:100040000C9449000C9449000C9449000C9449000C
:100050000C9449000C9449000C9449000C944900FC
:100060000C9449000C94490011241FBECFEFD8E036
:10007000DEBFCDBF11E0A0E0B1E0E8EAF1E002C0F0
:1000800005900D92A632B107D9F70E94CA000C94D0
:10009000D2000C9400001092C5008093C40088E147
:1000A0008093C10086E08093C20008959091C000C3
:1000B00095FFFCCF8093C60008950F931F93CF93B5
:1000C000DF93EC018C01060F111DC017D10721F041
:1000D00089910E945600F9CFDF91CF911F910F9126
:1000E00008958091C00087FFFCCF8091C6000895DD
:1000F0000F931F93CF93DF93EC018C01060F111D1B
:10010000C017D10721F00E9471008993F9CFDF91C8
:10011000CF911F910F910895CF93DF93CDB7DEB7A5
:100120002B970FB6F894DEBF0FBECDBF8BE0EBE18F
:10013000F1E0DE01119601900D928A95E1F76BE0F6
:10014000CE0101960E945D000E9471002B960FB6B1
:10015000F894DEBF0FBECDBFDF91CF910895FF921F
:100160000F931F93CF93DF93F82EC0E0D1E00CE103
:1001700011E0888184508F250E94560022960C172A
:100180001D07B9F78AE0DF91CF911F910F91FF9082
:100190000C94560087E60E944B000E948C000E943F
:1001A000AF00FBCFF894FFCF4F5551505D62795DA2
:1001B00073546F5770424355717A3E3842454378C5
:0E01C000773300456E746572206B65790A0016
:00000001FF
```

The Intel HEX is a transitional file format for microcontrollers, (E)PROMs, and other devices. The documentation states that HEXs can be converted to binary files and programmed into a configuration device.

```console
$ objcopy -I ihex chest.hex -O binary chest.bin ; xxd chest.bin
00000000: 0c94 3400 0c94 4900 0c94 4900 0c94 4900  ..4...I...I...I.
00000010: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000020: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000030: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000040: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000050: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000060: 0c94 4900 0c94 4900 1124 1fbe cfef d8e0  ..I...I..$......
00000070: debf cdbf 11e0 a0e0 b1e0 e8ea f1e0 02c0  ................
00000080: 0590 0d92 a632 b107 d9f7 0e94 ca00 0c94  .....2..........
00000090: d200 0c94 0000 1092 c500 8093 c400 88e1  ................
000000a0: 8093 c100 86e0 8093 c200 0895 9091 c000  ................
000000b0: 95ff fccf 8093 c600 0895 0f93 1f93 cf93  ................
000000c0: df93 ec01 8c01 060f 111d c017 d107 21f0  ..............!.
000000d0: 8991 0e94 5600 f9cf df91 cf91 1f91 0f91  ....V...........
000000e0: 0895 8091 c000 87ff fccf 8091 c600 0895  ................
000000f0: 0f93 1f93 cf93 df93 ec01 8c01 060f 111d  ................
00000100: c017 d107 21f0 0e94 7100 8993 f9cf df91  ....!...q.......
00000110: cf91 1f91 0f91 0895 cf93 df93 cdb7 deb7  ................
00000120: 2b97 0fb6 f894 debf 0fbe cdbf 8be0 ebe1  +...............
00000130: f1e0 de01 1196 0190 0d92 8a95 e1f7 6be0  ..............k.
00000140: ce01 0196 0e94 5d00 0e94 7100 2b96 0fb6  ......]...q.+...
00000150: f894 debf 0fbe cdbf df91 cf91 0895 ff92  ................
00000160: 0f93 1f93 cf93 df93 f82e c0e0 d1e0 0ce1  ................
00000170: 11e0 8881 8450 8f25 0e94 5600 2296 0c17  .....P.%..V."...
00000180: 1d07 b9f7 8ae0 df91 cf91 1f91 0f91 ff90  ................
00000190: 0c94 5600 87e6 0e94 4b00 0e94 8c00 0e94  ..V.....K.......
000001a0: af00 fbcf f894 ffcf 4f55 5150 5d62 795d  ........OUQP]by]
000001b0: 7354 6f57 7042 4355 717a 3e38 4245 4378  sToWpBCUqz>8BECx
000001c0: 7733 0045 6e74 6572 206b 6579 0a00       w3.Enter key..
```

Note that we can also use the online tool [matrixstorm](http://matrixstorm.com/avr/hextobin/ihexconverter.html) to do this.

Now that we have our binary, we need to identify which architecture it was compiled for.

``` console
file chest.bin
chest.bin: data
```

Well, our beloved friend `file` didn't recognize the file format. At that point, we have several options to discover the architecture:

* compiling a sample project for many architectures and clustering the outputs using correlation techniques like binary diffing in the hope of identifying the correct architecture
* try disassembling for many architectures in the hope of discovering the right code
* googling the HEX

The Googling technique is definetly the fastest and the easiest. It gives us a
lot of results concerning [AVR](https://www.microchip.com/en-us/products/microcontrollers-and-microprocessors/8-bit-mcus/avr-mcus).
Let's give the `avr-objdump` disassembler a try:

```console
$ avr-objdump -m avr -D chest.hex

00000000 <.sec1>:
   0:    0c 94 34 00     jmp    0x68    ;  0x68
   4:    0c 94 49 00     jmp    0x92    ;  0x92
   8:    0c 94 49 00     jmp    0x92    ;  0x92
   c:    0c 94 49 00     jmp    0x92    ;  0x92
  10:    0c 94 49 00     jmp    0x92    ;  0x92
  14:    0c 94 49 00     jmp    0x92    ;  0x92
  18:    0c 94 49 00     jmp    0x92    ;  0x92
  1c:    0c 94 49 00     jmp    0x92    ;  0x92
  20:    0c 94 49 00     jmp    0x92    ;  0x92
  24:    0c 94 49 00     jmp    0x92    ;  0x92
  28:    0c 94 49 00     jmp    0x92    ;  0x92
  2c:    0c 94 49 00     jmp    0x92    ;  0x92
  30:    0c 94 49 00     jmp    0x92    ;  0x92
  34:    0c 94 49 00     jmp    0x92    ;  0x92
  38:    0c 94 49 00     jmp    0x92    ;  0x92
  3c:    0c 94 49 00     jmp    0x92    ;  0x92
  40:    0c 94 49 00     jmp    0x92    ;  0x92
  44:    0c 94 49 00     jmp    0x92    ;  0x92
  48:    0c 94 49 00     jmp    0x92    ;  0x92
  4c:    0c 94 49 00     jmp    0x92    ;  0x92
  50:    0c 94 49 00     jmp    0x92    ;  0x92
  54:    0c 94 49 00     jmp    0x92    ;  0x92
  58:    0c 94 49 00     jmp    0x92    ;  0x92
  5c:    0c 94 49 00     jmp    0x92    ;  0x92
  60:    0c 94 49 00     jmp    0x92    ;  0x92
  64:    0c 94 49 00     jmp    0x92    ;  0x92
  68:    11 24           eor    r1, r1

[...]

  92:    0c 94 00 00     jmp    0    ;  0x0

[...]
```

We can deduce from the first bytes that this is valid code. Indeed, we are looking at a 26-entries vector table. 

We know that this code is targeting an Atmel AVR microcontroller, but which one?
Here is a [list of the most common ones](https://gcc.gnu.org/onlinedocs/gcc/AVR-Options.html), and here is a [matrix](/posts/img/ECW2021_chest/avr_matrix.png) listing some of their available features.

Again, we have multiple options to discover the correct microcontroller:

* compiling samples with all the different MCU types supported by `avr-gcc` and, again, use some correlation techniques against our dump
* searching more information about what we already know, like the [interrupt vectors](https://ece-classes.usc.edu/ee459/library/documents/avr_intr_vectors/)
* googling the code

Again, the googling technique is the fastest and the less painful. We can
quickly find a [dump like ours](https://stackoverflow.com/q/17323757) that is targeting an ATmega328P.

We can proceed with a static analysis using the [AVR instruction set manual](/posts/misc/ECW2021_chest/atmel-0856-avr-instruction-set-manual.pdf)
and the [ATMega328P datasheet](/posts/misc/ECW2021_chest/ATmega328-328P_Datasheet_Full.pdf):

```console
[...]

  __decode:
   15e:    ff 92           push   r15
   160:    0f 93           push   r16
   162:    1f 93           push   r17
   164:    cf 93           push   r28
   166:    df 93           push   r29
   168:    f8 2e           mov    r15, r24
   16a:    c0 e0           ldi    r28, 0x00
   16c:    d1 e0           ldi    r29, 0x01
   16e:    0c e1           ldi    r16, 0x1C
   170:    11 e0           ldi    r17, 0x01
   172:    88 81           ld     r24, Y
   174:    84 50           subi   r24, 0x04     ; acc -= 4
   176:    8f 25           eor    r24, r15      ; acc ^= user input key
   178:    0e 94 56 00     call   0xac          ; __usart_transmit_byte
   17c:    22 96           adiw   r28, 0x02     ; i += 2
   17e:    0c 17           cp     r16, r28
   180:    1d 07           cpc    r17, r29
   182:    b9 f7           brne   .-18          ; loop
   184:    8a e0           ldi    r24, 0x0A     ; r24 = '\n'
   186:    df 91           pop    r29
   188:    cf 91           pop    r28
   18a:    1f 91           pop    r17
   18c:    0f 91           pop    r16
   18e:    ff 90           pop    r15
   190:    0c 94 56 00     jmp    0xac          ; __usart_transmit_byte('\n')

  __main:
   194:    87 e6           ldi    r24, 0x67     ; UBRR
   196:    0e 94 4b 00     call   0x96          ; __usart_init(UBRR)
   19a:    0e 94 8c 00     call   0x118         ; while __decode(__display_prompt())
   19e:    0e 94 af 00     call   0x15e         ;
   1a2:    fb cf           rjmp   .-10

[...]

  __flag:   ; OUQP]by]sToWpBCUqz>8BECxw3
   1a8:     4f 55 51 50 5d 62 79 5d 73 54 6f 57 70 42 43 55 71 7a 3e 38 42 45 43 78 77 33

  __prompt: ; Enter key
   1c3:     45 6e 74 65 72 20 6b 65 79 0a 00
```

There is a decoding routine at `0x15e` for the encoded flag at `0x1a8`. This
routine needs a xor key, which is received using a serial line. We can pursue
the static analysis by bruteforcing the key. This python script will do the job:

```python
encoded = "OUQP]by]sToWpBCUqz>8BECxw3"
rot_key = 4
for xor_key in range(0xFF):
    decoded = "".join(
        [
            chr((ord(char) - rot_key) ^ xor_key)
            for i, char in enumerate(encoded)
            if not i % 2
        ]
    )
    if decoded.casefold().startswith("ecw{"):
        print(f"{xor_key:#04x}: {decoded}")
```

```console
$ python3 decode.py
0x0e ECW{aeb1c401}
```

Another approach was to emulate the MCU and bruteforce the key like this:

```console
$ qemu-system-avr -S -s -nographic -serial tcp::5678,server=on,wait=off -machine uno -bios chest.bin
$ printf "\x0e" | nc localhost 5678
ECW{aeb1c401}
```

I hope you enjoyed it as much as I did, see you next year!

## FSB as a service

The downloadable [archive](/posts/binaries/ECW_2021/fsb_as_a_service.txz) contains elements used to build the docker image you can access online. It contains:

* a dynamic loader
* a C library
* a challenge binary

Let's start with a basic `checksec`:

```console
pwn checksec challenge
[*] '/Users/gteissier/Downloads/ecw2021-fsb_as_a_service/challenge'
    Arch:     aarch64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The binary is rather small, compiled for aarch64, and we spot three things:

```console
0000000000000a90 <shell>:
 a90:	d503233f 	paciasp
 a94:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
 a98:	910003fd 	mov	x29, sp
 a9c:	90000000 	adrp	x0, 0 <__abi_tag-0x254>
 aa0:	91318000 	add	x0, x0, #0xc60
 aa4:	97ffff9f 	bl	920 <system@plt>
 aa8:	d503201f 	nop
 aac:	a8c17bfd 	ldp	x29, x30, [sp], #16
 ab0:	d65f0bff 	retaa
```

1. The binary is cool enough to give us a shell function! `paciasp` and `retaa` are ARMv8.3 pointer-authentication instructions, they shield integrity of return addresses stored on the stack. Curious French readers can go and enjoy this [article](https://connect.ed-diamond.com/MISC/misc-113/armv8.5-un-support-materiel-contre-les-bugs-memoires).

```console
0000000000000ab4 <make_readonly>:
 ab4:	d503233f 	paciasp
 ab8:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
 abc:	910003fd 	mov	x29, sp
 ac0:	b0000080 	adrp	x0, 11000 <__FRAME_END__+0x10208>
 ac4:	f947f400 	ldr	x0, [x0, #4072]
 ac8:	9274cc00 	and	x0, x0, #0xfffffffffffff000
 acc:	52800022 	mov	w2, #0x1                   	// #1
 ad0:	d2820001 	mov	x1, #0x1000                	// #4096
 ad4:	97ffffa7 	bl	970 <mprotect@plt>
 ad8:	b9401fe0 	ldr	w0, [sp, #28]
 adc:	7100001f 	cmp	w0, #0x0
 ae0:	54000060 	b.eq	aec <make_readonly+0x38>  // b.none
 ae4:	52800040 	mov	w0, #0x2                   	// #2
 ae8:	97ffff7a 	bl	8d0 <_exit@plt>
 aec:	d503201f 	nop
 af0:	a8c27bfd 	ldp	x29, x30, [sp], #32
 af4:	d65f0bff 	retaa
```

2. A memory region is made read-only. Further examination reveals the memory region made read-only contains `__malloc_hook`, and this page also coincidently contains other hooks such as `__realloc_hook` or `__free_hook`.

```console
0000000000000af8 <main>:
 af8:	d503233f 	paciasp
 afc:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
 b00:	910003fd 	mov	x29, sp
... boring setbuf follows
 b40:	d2801000 	mov	x0, #0x80                  	// #128
 b44:	97ffff6f 	bl	900 <malloc@plt>		// buf = malloc(0x80)
 b48:	f9000fe0 	str	x0, [sp, #24]
 b4c:	f9400fe0 	ldr	x0, [sp, #24]
 b50:	f100001f 	cmp	x0, #0x0
 b54:	54000061 	b.ne	b60 <main+0x68>  // b.any
 b58:	52800020 	mov	w0, #0x1                   	// #1
 b5c:	97ffff5d 	bl	8d0 <_exit@plt>
 b60:	97ffffd5 	bl	ab4 <make_readonly>		// turn malloc_hook and the like read-only from now on
 b64:	d2801002 	mov	x2, #0x80                  	// 0x80
 b68:	f9400fe1 	ldr	x1, [sp, #24]			// buf, allocated at 0xb44
 b6c:	52800000 	mov	w0, #0x0                   	// #0, stdin fileno
 b70:	97ffff78 	bl	950 <read@plt>
 b74:	b90017e0 	str	w0, [sp, #20]
 b78:	b94017e0 	ldr	w0, [sp, #20]
 b7c:	7100041f 	cmp	w0, #0x1
 b80:	5400012d 	b.le	ba4 <main+0xac>
 b84:	b98017e0 	ldrsw	x0, [sp, #20]
 b88:	d1000400 	sub	x0, x0, #0x1
 b8c:	f9400fe1 	ldr	x1, [sp, #24]
 b90:	8b000020 	add	x0, x1, x0
 b94:	3900001f 	strb	wzr, [x0]
 b98:	f9400fe0 	ldr	x0, [sp, #24]			// buf
 b9c:	97ffff71 	bl	960 <printf@plt>		// printf(buf)
 ba0:	17fffff1 	b	b64 <main+0x6c>			// while true
 ba4:	d503201f 	nop
 ba8:	52800060 	mov	w0, #0x3                   	// #3
 bac:	97ffff49 	bl	8d0 <_exit@plt>
```

3. After having allocated a buffer from heap, the hooks' page is made read-only. This buffer is then used to read from stdin, and the buffer is directly fed to printf. We have a format string! There is no limit on the number of calls to `printf` we can do, thus we may:

* leak values in stack located below our frame: stack and code locations
* modify values through the use of `%n` and its variants

Taking the above a bit further, we can find stack values that point to stack itself, so all in all we can forge arbitrary values on the stack, and later gain arbitrary read and write.

However, to go further, we need to turn arbitrary write to code execution:

* The stack does not look easily malleable: return addresses are protected through the use of `paciasp` / `retaa`;
* Dynamic memory hooks have been turned read-only: there is no hope in overwriting them;
* Inserting a destructor is made useless by the use of `_exit`.

How to gain code execution then? There are a number of options, but looking at files contained in the initial archive, we spot a hidden file, `.gdb_history`.
This dot file is indeed a hint: `disassemble register_printf_specifier`.

```c
/* Register FUNC to be called to format SPEC specifiers; ARGINFO must be
   specified to determine how many arguments a SPEC conversion requires and
   what their types are.  */
extern int register_printf_specifier (int __spec, printf_function __func,
                                      printf_arginfo_size_function __arginfo)
```

The code speaks for itself:

```c
int __register_printf_specifier (int spec, printf_function converter,
	                             printf_arginfo_size_function arginfo)
	{
	  if (spec < 0 || spec > (int) UCHAR_MAX)
	    {
	      __set_errno (EINVAL);
	      return -1;
	    }
	
	  int result = 0;
	  __libc_lock_lock (lock);
	
	  if (__printf_function_table == NULL)
	    {
	      __printf_arginfo_table = (printf_arginfo_size_function **)
	        calloc (UCHAR_MAX + 1, sizeof (void *) * 2);
	      if (__printf_arginfo_table == NULL)
	        {
	          result = -1;
	          goto out;
	        }
	
	      __printf_function_table = (printf_function **)
	        (__printf_arginfo_table + UCHAR_MAX + 1);
	    }
	
	  __printf_function_table[spec] = converter;
	  __printf_arginfo_table[spec] = arginfo;
	
	 out:
	  __libc_lock_unlock (lock);
	
	  return result;
	}
```

This is a little known feature of `glibc`: users can register custom printf specifiers through the use of `register_printf_specifier`. This function makes use of an array of function pointers indexed by the char specifier. We can leverage this feature to overwrite one element of the array and later call `printf` with the associated specifier: the overwritten address will be called!

## WYSIWYG

### Hints

Let's start with the hints that were there!

Executing the challenge gives a message:
```
$ ./wysiwyg
Welcome to the challenge !
```

The thing is that when you disassemble the challenge you won't see the corresponding call to printf. This was a first line of approach.

Now, executing it with an input will give you:

```
$ ./wysiwyg toto
Welcome to the challenge !
Your key is:
toto
The message should be deciphered correctly if you did things right ;)
Nop !
```

If you're a try-harder and execute it a second time you would get:

```
$ ./wysiwyg toto
Welcome to the challenge !
Your key is:
Are 
The message should be deciphered correctly if you did things right ;)
Nop !
```

What you see here is that the announced key (after *Your key is:* has changed). This was a second line of approach.

### Main function

The main function of the challenge is not very helpful and quite weird at first read.
If you give an argument it reads a file called *text.txt* into `argv[1]` with a length equal to `strlen(argv[1])`.
It then copies `argv[1]` up to a maximum of 32 bytes in a buffer and prints it after *Your key is*.

The first 8 bytes of the key are set to upper case and the rest of the key is *xored* with the result of `sqrt(log(1337.3615)) + sinh(asinh(3615.1337))`.

Using mbedTLS this key will be used to decipher a message using AES-CBC with an IV set to `"yolo pour l'iv!"`

Finally a `sha1` is computed on the deciphered message and if it's the right one, it's printed and it gives you the flag.

What must be seen here (and I hope you didn't reversed too much cryptography because it was some kind of trap!) is that the input you gave is not used which is weird.
You must find where the input affects the challenge.

### Back to hints!

The second time we execute the challenge, we get a different key after *Your key is:* even if we did not create and write something in *text.txt*. So something is done with *text.txt* elsewhere in the binary.

In the same way, *Welcome to the challenge !* is not printed in the main and there is no associated call to `printf` anywhere in the binary. definitively something is executed elsewhere.

### Constructor function

!SPOILER ALERT! The binary is going to play with the loader by changing the resolved functions.

If you look closely, there is a constructor function (*`__attribute__ ((constructor))`*).

This function finds the base address of the binary by reading the beginning of the pages starting from the one that contains the current function and going up until it reads the magic `\x7fELF` (0x7f454c46).

Then it parses the ELF file header to find the `.dynamic` (PT_DYNAMIC) section
(see [here](https://code.woboq.org/linux/include/elf.h.html) and [here](https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html)).

Once it has the .dynamic section, it finds other information it needs about the binary:
* the address of the GOT (specifically the `.got.plt`): `DT_PLTGOT`
* the address of the symbol table: `DT_SYMTAB`
* the address of the string table: `DT_STRTAB`
* the address of the PLT relocations : `DT_JMPREL`
* the size in bytes of the PLT relocations : `DT_PLTRELSZ`
* the size of one of the PLT relocation: `DT_RELAENT`

If your are not familiar with how the PLT and the GOT work please go and check [this](https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html) or [here](https://ypl.coffee/dl-resolve/). The challenge is compiled with *lazy-bindings*.

The challenge then gets the offsets in the `.got.plt` of the following functions using the symbol table, the string table, and the PLT relocations:
* `read`
* `write`
* `__memcpy_chk`
* `__printf_chk`
* `sinh`
* `log`
* `sqrt`
* `asinh`.

<u>**Notes:**</u>

* `.got.plt` is the part of the GOT patched by `_dl_runtime_resolve` (ld.so) when symbols are resolved thanks to the PLT.
* In the challenge, all the strings that are not in main are obfuscated in the same way. Characters with even offsets are xored with 0x25 and the ones with odd offsets with 0x11.

It then calls `printf` with the message *Welcome to the challenge !* by calling the good `.got.plt` entry which will resolve `printf` address.

The current state of the GOT is saved and a **hook** is installed on future calls to `_dl_runtime_resolve`.
So now each time a function is resolved our hook is called.

### The hook

Before `_dl_runtime_resolve` is called 2 arguments are pushed on the stack: the context associated to `_dl_runtime_resolve` and the GOT offset of the function to be resolved. `_dl_runtime_resolve` cleans these arguments before calling the resolved function. Also when `_dl_runtime_resolve` is called, some volatile registers contains the arguments of the function to be resolved.
Because of this, the process is in a tricky state where quite a lot of bugs and segmentation faults can appear. To avoid this, a small trampoline is called as a *pre-hook* function to store or clean what needs to be.

The trampoline also installs a *post-hook* to be called after the resolved function to restore the GOT with the state saved during the contructor function. This is done so that our hook is always called even if a function was already resolved.

The hook acts differently depending on the resolved function.
* read: checks if a file called *change_me.txt* exists in the current folder and **swaps read with write**. read and write have the same prototypes.
* write: checks if a file called *change_me.txt* exists in the current folder and **swaps write with read**.
* memcpy (precisely *__memcpy_chk*): opens *text.txt* and writes the content of a buffer containing "Are your sure about the formula ?" in it. It then parses the buffer with a custom `sscanf` function using the format string `%x_%d-%d_%d-%d_%d-%d_%d-%d`.
* The last effects can swap `sqrt`, `log`, `sinh` and `asinh` but it will be explained later in the write-up.

<u>**Note:**</u>

I hope you understood that it was `sscanf` just by looking at the input and output of the function... Otherwise, I'm sorry, it might have been hard! While developping the challenge, it kept on breaking the stack and the arguments of the resolved function when calling `sscanf`. This came from variadic arguments which were a pain to use in the context of a hook of `_dl_runtime_resolve`. In the end, I decided to use a custom `sscanf` using [musl](https://musl.libc.org/) to remove variadic arguments.

### Take a step back

The main:
* reads the context of *text.txt* into `argv[1]` with a length of `strlen(argv[1])`
* memcpy it into a 32 bit buffer and prints the key.
* XOR this buffer with the result of `sqrt(log(1337.3615)) + sinh(asinh(3615.1337))`.
* Uses the buffer to decipher a message.

But if we also look at the hook (without creating a *chang_me.txt* file for the moment) we get:
* reads the context of *text.txt* into `argv[1]` with a length of `strlen(argv[1])`
* memcpy is resolved, the hook writes "Are your sure about the formula ?" in *text.txt* if the file exists.
* memcpy `argv[1]` it into a 32 bit buffer and prints the it.
* XOR this buffer with the result of `sqrt(log(1337.3615)) + sinh(asinh(3615.1337))`.
* Uses the buffer to decipher a message.

That is why the second time you execute the challenge a part of "Are your sure about the formula ?" is printed, `strlen(argv[1])` characters to be precise.

### Resolution

Now, if you create a file named *chang_me.txt* this is what happens:

* read is called but is changed to write by the hook so `argv[1]` is written to *text.txt*
* memcpy is resolved, the hook calls write but it is changed to read. So the file *text.txt* is read in a buffer which is then parsed by a `sscanf` using the format string `%x_%d-%d_%d-%d_%d-%d_%d-%d`. The first `%x` is a magic that is checked later and the `%d` are stored in an array.
* memcpy `argv[1]` into a 32 bit buffer and print it.
* `sqrt(log(1337.3615)) + sinh(asinh(3615.1337))` is computed. This will call the hook at the resolution of `sqrt`, `log`, `sinh` and `asinh`. If the magic parsed by the `sscanf` is equal to *0xfacebeef* these four functions will be swapped using the indexes you gave. In the format string `%x_%d-%d_%d-%d_%d-%d_%d-%d` each `%d-%d` corresponds to a permutation, you must give the indexes of `sqrt` (26), `log` (12), `sinh` (19) and `asinh` (30) otherwise it will not work. In other words you can control the formula of this computation through `argv[1]`.
* XOR the buffer with the result of the previous computation.
* Use the buffer to decipher a message.

To summarize, to resolve the challenge you must create a file called *chang_me.txt* and then find the correct formula by bruteforcing (there is only 256 possibilities and the main returns -1 if you failed).

Finally you will get:
```
$ touch change_me.txt
$ ./wysiwyg facebeef_26-19_12-26_19-30_30-12
Welcome to the challenge !
Your key is:
facebeef_26-19_12-26_19-30_30-12
The message should be deciphered correctly if you did things right ;)
Good job ! ;) Your flag is:
ECW{H4v3_FuN_1n_7H3_L0D3R}
```

I hope you liked it and that you learned things about the loader!

## Conclusion

We hope you had fun with these challenges and you definitely learned something even if you did not get through it. We will be glad to meet you during the CTF final and discuss about theses challenges and uncover our jobs in more details.

We look forward to reading your write-ups and techniques you used in order to solve these challenges.

## Internships 2022

* [Fuzzing Android System Services](https://emploi.thalesgroup.com/emploi/rennes/fuzzing-android-system-services-stage-h-f/17883/16071146400)
* [AI assisted Fuzzing](https://emploi.thalesgroup.com/emploi/rennes/ai-assisted-fuzzing-stage-h-f/17883/15757478912)
* [Windows attack surface analyzer](https://emploi.thalesgroup.com/emploi/rennes/windows-attack-surface-analyzer-stage-h-f/17883/15757478816)
* [Leveraging Android custom permissions](https://jobs.thalesgroup.com/job/rennes/leveraging-android-custom-permissions-stage-h-f/1766/15757545888)
* [Frontend GDB avec Dear ImGui en Rust](https://jobs.thalesgroup.com/job/rennes/frontend-gdb-avec-dear-imgui-en-rust-stage-h-f/1766/15757546896)

All thalium's offers can be found at [Thales job portal](https://jobs.thalesgroup.com/search-jobs/thalium).
