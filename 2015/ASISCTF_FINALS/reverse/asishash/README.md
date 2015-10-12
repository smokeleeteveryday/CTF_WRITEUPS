# ASISCTF Finals 2015: ASIS Hash

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASISCTF Finals 2015 | ASIS Hash | Reversing |    150 |

**Description:**
>*Find the flag in this [file](challenge/hash.elf).*

----------
## Write-up

We're provided with a 64-bit ELF binary which takes a command line argument and checks it against some internal variable to indicate the argument you entered was the correct flag:

```bash
$ ./hash.elf
Usage: ./hash.elf flag 
```

The binary contains a regular `ptrace`-based anti-debugging check which we immediately patch/nop out using IDA. The code deciding whether the flag is correct or not is here:

```c
 if ( v2 == 2 )
  {                                          
    __sprintf_chk((__int64)&inp_buffer, 1LL, 1024LL, 0x401CC4LL, *(_QWORD *)(v3 + 8));
    pass_out = (const char *)hash((__int64)&inp_buffer);
    v11 = strcmp(pass_out, (const char *)&v14);
    if ( v11 )
    {
      v11 = 0;
      puts("Sorry! flag is not correct!");
    }
    else
    {
      puts("Congratz, you got the flag :) ");
    }
  }
```

To save us some reverse engineering time we want to obtain the value our (processed) flag is matched against so we use a small `LD_PRELOAD` script to hook `strcmp` and dump its arguments:

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Function prototypes for hook, to be used as type for original function resolution
typedef int (*orig_strcmp_f_type)(char *s1, char *s2);

int strcmp(char *s1, char *s2)
{
  orig_strcmp_f_type orig_strcmp;
  orig_strcmp = (orig_strcmp_f_type)dlsym(RTLD_NEXT,"strcmp");

  printf("[%s] [%s]\n", s1, s2);

  return orig_strcmp(s1, s2);
}
```

Which gives us:

```bash
$ LD_PRELOAD=./hook.so ./hash.elf kek
[193633239] [27221558106229772521592198788202006619458470800161007384471764]
Sorry! flag is not correct!
```

Given the challenge name and values involved we can probably assume this is some sort of hash and `27221558106229772521592198788202006619458470800161007384471764` represents the hash of our target flag.

The pseudo-code for the hashing function looks as follows:

```c
signed __int64 __fastcall hash(__int64 user_input)
{
  __int64 v1; // rbx@1
  __int64 v2; // r8@1
  const char *v3; // rax@2
  __int64 v4; // rax@2
  __int64 v5; // rdx@3
  __int64 v7; // [sp+0h] [bp-48h]@2
  __int64 v8; // [sp+28h] [bp-20h]@1

  v1 = user_input + 1;
  v8 = *MK_FP(__FS__, 40LL);
  __sprintf_chk(0x6030E0LL, 1LL, 1024LL, 0x401CCBLL, 0x1505LL);// sprintf(bss_dst_buffer, "%d", 0x1505);
  v2 = *(_BYTE *)user_input;
  if ( *(_BYTE *)user_input )
  {
    do
    {
      LOBYTE(v2) = v2 ^ 0x8F;
      __sprintf_chk((__int64)&v7, 1LL, 40LL, 0x401CCELL, v2);// sprintf(bss_dst_buffer, "%d in honor of 0x8F", v2);
      ++v1;
      *strchr((const char *)&v7, 0x20) = 0;
      v3 = (const char *)sub_4012D0(bss_dst_buffer);// returns ptr to hvalholder = 0x703920
      v4 = sub_400BD0(v3, (const char *)&v7);
      __sprintf_chk(0x6030E0LL, 1LL, 1024LL, 0x401CC4LL, v4);// sprintf(bss_dst_buffer, "%s", v4);
      v2 = *(_BYTE *)(v1 - 1);
    }
    while ( *(_BYTE *)(v1 - 1) );
  }
  v5 = *MK_FP(__FS__, 40LL) ^ v8;
  return 0x6030E0LL;                            // bss_dst_buffer
}
```

It looks like the hashing function iterates over the characters of our input string, XORs them with 0x8F and converts the result to a string holding the decimal representation which is stored in v7. The subroutines called by the hashing function are a little convoluted and instead of statically reversing them we load the binary into gdb, set breakpoints before and after the subroutine calls and observe the values of `v3`, `v4` and `v7` and see if we can learn something about the hashing algorithm from them:

```bash
gdb-peda$ b *0x401BD0
Breakpoint 1 at 0x401bd0
gdb-peda$ b *0x401BD6
Breakpoint 2 at 0x401bd6
gdb-peda$ b *0x401BDB
Breakpoint 3 at 0x401bdb
gdb-peda$ r ABCD

Iteration 0:
  RAX: 0x703920 --> 0x333735373731 ('177573')
  RSP: 0x7fffffffe370 --> 0x68206e6900363032 ('206')
  RAX: 0x804181 --> 0x393737373731 ('177779')

Iteration 1:
  RAX: 0x703920 --> 0x37303736363835 ('5866707')
  RSP: 0x7fffffffe370 --> 0x68206e6900353032 ('205')
  RAX: 0x804181 --> 0x32313936363835 ('5866912')

Iteration 2:
  RAX: 0x703920 ("193608096")
  RSP: 0x7fffffffe370 --> 0x68206e6900343032 ('204')
  RAX: 0x804181 ("193608300")
```

If we look at the above we can indeed see our string characters are taken and XORed with 0x8F (A ^ 0x8F = 0x41 ^ 0x8F = 206). We can also see the call to `sub_400BD0` apparently simply adds `v3` and `v7` (177573 + 206 = 177779) while `sub_4012D0` seems to multiply v3 result by 33 and multiple runs reveal v3 always starts at 177573. So without having to look at the subroutines we can conclude this is a multiplicative hash function initial state = 0x1505 (177573/33), multiplier = 33 and no modulus (which we can conclude from the fact that we can feed arbitrarily large strings which result in corresponding increases in hash size). In Python the hash function looks as follows:

```python
def hashf(s):
    # Multiplier
    M = 0x21
    # Initial state
    state = 0x1505
    for c in s:
        state = ((state * M) + (ord(c) ^ 0x8F))
    return state
```

While similar in many ways to the [simple_hash](https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/MMACTF/reversing/simple_hash) challenge of this year's MMACTF this hash function is a little different in that the multiplier is not a prime number (making direct reversal impossible) and the XOR operation complicates the boundary-check on our divide-and-conquor approach from that CTF. However since there is no modulus involved we can simply bruteforce the input on a byte-by-byte basis (especially given that we know the last character is }, the first 5 characters are ASIS{ and there are 32 characters in between in lowercase hex as per the flag format) using [the following script](solution/hash_crack.py):

```python
#!/usr/bin/env python
#
# ASISCTF Finals 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

def hashf(s):
    # Multiplier
    M = 0x21
    # Initial state
    state = 0x1505
    for c in s:
        state = ((state * M) + (ord(c) ^ 0x8F))
    return state

def recover_m(h):
  charset = "0123456789abcdef"

  M = 0x21
  I = hashf("ASIS{")
  s = "}"

  h -= (ord("}") ^ 0x8F)
  h /= M

  while (h > I):
    for c in charset:
      if ((h - (ord(c) ^ 0x8F)) % M == 0):
        s += c
        h -= (ord(c) ^ 0x8F)
        h /= M

  s += "{SISA"

  return s[::-1]

h = 27221558106229772521592198788202006619458470800161007384471764
print recover_m(h)
```

Which gives us:

```bash
$ ./hash_crack.py
ASIS{d5c808f5dc96567bda48be9ba82fc1d6}
```