# DEF CON CTF Quals 2016: step

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| DEF CON CTF Quals | step | Reversing | 2 |

### Description
> Step by step.
>
> Running at step_8330232df7a7e389a20dd37eb55dfc13.quals.shallweplayaga.me:2345

## Write-up

We are given the address of a service running a binary and a copy of the [binary itself](challenge):

```bash
$ file step
step; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, stripped
$ ./step
Key1: 
```

Load it up into IDA and take a look at the `main` routine (which we can't decompile yet because of garbled/encrypted instructions halfway through):

```asm
.text:0000000000400FBB                 xor     eax, eax
.text:0000000000400FBD                 mov     edi, offset aKey1 ; "Key1: "
.text:0000000000400FC2                 mov     eax, 0
.text:0000000000400FC7                 call    _printf
.text:0000000000400FCC                 mov     rax, cs:stdout
.text:0000000000400FD3                 mov     rdi, rax
.text:0000000000400FD6                 call    _fflush
.text:0000000000400FDB                 mov     rdx, cs:stdin
.text:0000000000400FE2                 lea     rax, [rbp-10h]
.text:0000000000400FE6                 mov     esi, 6
.text:0000000000400FEB                 mov     rdi, rax
.text:0000000000400FEE                 call    _fgets
.text:0000000000400FF3                 mov     byte ptr [rbp-0Ch], 0
.text:0000000000400FF7                 lea     rax, [rbp-10h]
.text:0000000000400FFB                 mov     ecx, 49BFh
.text:0000000000401000                 mov     rdx, rax
.text:0000000000401003                 mov     esi, 9Eh
.text:0000000000401008                 mov     edi, offset mystery_buf_1
.text:000000000040100D                 call    validate_key_1
.text:0000000000401012                 lea     rax, [rbp-10h]
.text:0000000000401016                 mov     rdi, rax
.text:0000000000401019                 call    near ptr mystery_buf_1
```

The binary asks us for a key which is then passed to a routine we named `validate_key_1` together with the address of a buffer we named `mystery_buf_1` and the arguments 0x49BF and 0x9E. If we decompile `validate_key_1` we see the following:

```c
      v5 = 0;
      checksum = 0;
      for ( i = a1_rdi; &a1_rdi[a2_esi] > i; ++i )
      {
        *i ^= *(_BYTE *)(v5 + a3_rdx);
        checksum += *i;
        v5 = (char)(v5 + 1) % 4;
      }
      result = checksum;
      if ( checksum != a4_ecx )
      {
        printf("Failed");
        exit(0);
      }
      return result;
```

This is a simple repeating-key xor cipher which applies our 4-byte supplied key to a buffer of length `0x9E` starting from `mystery_buf_1` and maintains an additive checksum which has to sum to `0x49BF`. Relying on the checksum to recover the key would pose a problem as there is a large keyspace of colliding keys producing a valid checksum for the given buffer. So instead we take a look at the `main` routine and see `mystery_buf_1` is, after decryption, called as a function:

```asm
.text:0000000000401012                 lea     rax, [rbp-10h]
.text:0000000000401016                 mov     rdi, rax
.text:0000000000401019                 call    near ptr mystery_buf_1
```

Now functions start with function prologues and on x86-64 these tend to start with:

```asm
    push    rbp
    mov     rbp, rsp
```

Which in hex looks like `55 48 89 E5` which gives us 4 bytes of candidate plaintext from which we can derive a candidate key (simply XOR the first 4 bytes of ciphertext starting at `mystery_buf_1` with `55 48 89 E5`, which produces key "RotM") which happens to match the checksum. We can further validate this key by connecting to the remote service and entering it:

```bash
$ nc step_8330232df7a7e389a20dd37eb55dfc13.quals.shallweplayaga.me 2345
Key1: RotM
Key2: 
```

Looks like this is the correct first key. Let's rename `mystery_buf_1` to `mystery_routine_1` and use the following IDA python script to decrypt the routine:

```python
def repeating_key_xor(start_address, buffer_len, key):
    for i in xrange(buffer_len):
        c = idaapi.get_byte(start_address + i) ^ ord(key[(i % len(key))])
        idaapi.patch_byte(start_address + i, c) 
    return

# Step 1
repeating_key_xor(0x400E0E, 0x9E, "RotM")
```

And then disassemble the result and decompile it:

```c
void __usercall mystery_routine_1(__int64 _RBX@<rbx>, __int64 a2@<rdi>, long double a3@<st0>)
{
  unsigned __int64 v3; // rt0@2
  long double v4; // fst7@2
  int _EAX; // eax@2
  __int16 *v6; // [sp+10h] [bp-A0h]@1
  __int64 v7; // [sp+18h] [bp-98h]@1
  int v8; // [sp+98h] [bp-18h]@1
  __int64 v9; // [sp+A8h] [bp-8h]@1

  v9 = *MK_FP(__FS__, 40LL);
  validate_key_1(&mystery_buf_2, 0xEC, a2, 0x49C3);
  v6 = &mystery_buf_2;
  v8 = 4;
  sigfillset((sigset_t *)&v7);
  sigaction(5, (const struct sigaction *)&v6, 0LL);
  v3 = __readeflags();
  __writeeflags(v3 | 0x100);
  v4 = a3 * (long double)*(signed __int16 *)(_RBX + 0x48FEF845);
  _EAX = v28 ^ (v3 | 0x100);
  __asm { xlat }
  JUMPOUT(__CS__, *(_QWORD *)(_RBX + 104));
}
```

We can see our routine is called as follows:

```asm
.text:0000000000401012                 lea     rax, [rbp-10h]
.text:0000000000401016                 mov     rdi, rax
.text:0000000000401019                 call    mystery_routine_1
```

Which means it is called with key1 ("RotM") as argument. There seems to be something weird going on toward the end of the routine though, let's take a clarifying look in the disassembly:

```asm
.text:0000000000400E8B                 pushfq
.text:0000000000400E8C                 pop     rax
.text:0000000000400E8D                 or      rax, 100h
.text:0000000000400E93                 push    rax
.text:0000000000400E94                 popfq
.text:0000000000400E95                 nop
.text:0000000000400E96                 fimul   word ptr [rbx+48FEF845h]
.text:0000000000400E9C                 xor     eax, ds:28h
.text:0000000000400EA3                 xlat
.text:0000000000400EA4                 add     eax, 0FFF8D64Dh
.text:0000000000400EA9                 jmp     qword ptr [rbx+68h]
```

It looks like a bunch of nonsensical/invalid FPU operations are being executed. This starts to make sense, however, after we investigate the signal handling stuff in the routine.

We can see our mystery routine calls the repeating-key xor validation/decryption routine again but this time on a different buffer and with different parameters:

```c
validate_key_1(&mystery_buf_2, 0xEC, a2, 0x49C3);
```

This decrypts another routine whose address is subsequently passed as a signal handler argument to a `sigaction` call specifying a handler for `SIGTRAP (5)` signals:

```c
v6 = &mystery_buf_2;
sigfillset((sigset_t *)&v7);
sigaction(5, (const struct sigaction *)&v6, 0LL);
```

Which means that upon a SIGTRAP being raised mystery_buf_2 will be invoked. Lets apply our IDA script again to `mystery_buf_2` to decrypt it and decompile the result to see what that routine does:

```c
__int64 __fastcall mystery_routine_2(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // [sp+48h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  stor_ptr = storage_area;
  storage_area = *(_QWORD *)(a3 + 0xA8);
  if ( (unsigned __int64)storage_area > 0x400935 && (unsigned __int64)storage_area <= 0x40103D )
  {
    if ( (unsigned __int64)stor_ptr > 0x400935 && (unsigned __int64)stor_ptr <= 0x40103D )
      *(_BYTE *)stor_ptr ^= stor_ptr;
    *(_BYTE *)storage_area ^= storage_area;
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

We can see this routine is passed 3 arguments, the 3rd of which is offset with `0xA8` and then dereferenced to load a QWORD. A check is then made on the result to see whether it resides in appropriate range and if so the byte at that value (treated as an address) is XORed with the least significant byte of the address itself. This seems to be a decryption routine for decoding instructions using their address as a key. But at what address does it start decoding? We know the routine is invoked as a signal handler for `SIGTRAP` signals and the third argument passed to signal handlers is a `void* ucontext_t`. So we need to determine what is at offset `0xA8` [in this structure](http://pubs.opengroup.org/onlinepubs/7908799/xsh/ucontext.h.html) which looks as follows:

```c
ucontext_t* (pointer to ucontext_t)
sigset_t (structure or integer, usually unsigned long)
stack_t (structure)
    void *ss_sp
    size_t ss_size
    int ss_flags

mcontext_t (structure)
    gregset_t gregs;
    fpregset_t fpregs;
    unsigned long __reserved1 [8];
```

Where `typedef long int greg_t;`, `#define NGREG   23` and `typedef greg_t gregset_t[NGREG];`. So we know that on a 64-bit architecture `mcontext_t` starts at offset 40 within `ucontext_t` which means our value is at offset `(168 - 40 = 128)` within mcontext_t, making it register number 16 which is `REG_RIP`.

Hence we can conclude `mystery_routine_2` is invoked upon `SIGTRAP`, takes the address of the violating instruction and decrypts it (provided its address is within whitelisted range) before continuing making the application self-decrypting in an instruction-by-instruction fashion. The following IDA python snippet achieves this:

```python
def selfmod_decoder(rip_address):
    if ((rip_address > 0x400935) and (rip_address <= 0x40103D)):
        idaapi.patch_byte(rip_address, idaapi.get_byte(rip_address) ^ (rip_address & 0xFF))
    return
```

We couldn't be bothered to integrate this into an emulation approach so instead we simply worked through the application's codeflow and applied the above routine one instruction at a time. This allowed us to decode the epilogue of `mystery_routine_1` and trailing code in `main` after the call to `mystery_routine_1` which allows us to decompile `main` in full:

```c
  printf("Key1: ", a1, a2);
  fflush(stdout);
  fgets(&s, 6, stdin);
  v7 = 0;
  validate_key_1(mystery_routine_1, 158, (__int64)&s, 18879);
  mystery_routine_1(a3, (__int64)&s, a4);
  mystery_routine_3();
```

We can see after the call to `mystery_routine_1` which sets up the self-decryption mechanism there is a call to `mystery_routine_3` which, after decryption, looks as follows when decompiled:

```c
  stream = fopen("flag", "r");
  if ( !stream )
    exit(1);
  fgets(buffer, 64, stream);
  fclose(stream);
  printf("Key2: ");
  fflush(stdout);
  fgets(&key_2, 32, stdin);
  v15 = 0;
  ((void (__fastcall *)(char *, signed __int64))loc_400A22)(&key_2, 32LL);
  ((void (__fastcall *)(char *))loc_400C31)(&key_2);
```

So a flagfile is read and stored in a buffer in the `.bss` segment:

```asm
.bss:00000000006020E0 ; char buffer[64]
.bss:00000000006020E0 buffer          db 40h dup(?)           ; DATA XREF: mystery_routine_5+CFo
.bss:00000000006020E0                                         ; mystery_routine_3+5Do
.bss:00000000006020E0 _bss            ends
```

After which the binary requests a second key which it passes to an as-of-yet encrypted routine at `loc_400A22` and after that another routine at `loc_400C31`. We decrypted the last routine first resulting in the following:

```c
  char str1[6]; // [sp+10h] [bp-40h]@1
  char str2[32]; // [sp+20h] [bp-30h]@1
  __int64 v4; // [sp+48h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  str1[0] = 'n';
  str1[1] = 'o';
  str1[2] = 'p';
  str1[3] = 'e';
  str1[4] = '\n';
  str1[5] = '\0';
  str2[0] = 'P';
  str2[1] = 'l';
  str2[2] = 'e';
  str2[3] = 'a';
  str2[4] = 's';
  str2[5] = 'e';
  str2[6] = ',';
  str2[7] = ' ';
  str2[8] = 'm';
  str2[9] = 'a';
  str2[10] = 'y';
  str2[11] = ' ';
  str2[12] = 'I';
  str2[13] = ' ';
  str2[14] = 'h';
  str2[15] = 'a';
  str2[16] = 'v';
  str2[17] = 'e';
  str2[18] = ' ';
  str2[19] = 't';
  str2[20] = 'h';
  str2[21] = 'e';
  str2[22] = ' ';
  str2[23] = 'f';
  str2[24] = 'l';
  str2[25] = 'a';
  str2[26] = 'g';
  str2[27] = ' ';
  str2[28] = 'n';
  str2[29] = 'o';
  str2[30] = 'w';
  str2[31] = '\0';
  if ( !memcmp(a1, str2, 32uLL) )
    puts(buffer);
  else
    printf(str1);
```

As we can see two stack-constructed strings are made and the routine's argument is `memcmp'd` against the string "Please, may I have the flag now\0". If it matches the flag is output from its buffer, if it doesn't we get "nope". Since the argument to this routine is our second key we figured the penultimate routine at `loc_400A22` would do something to it in-memory which turned out to be true:

```c
__int64 __fastcall mystery_routine_4(__int64 a1)
{
  unsigned __int8 i; // [sp+1Fh] [bp-31h]@1
  __int64 s; // [sp+20h] [bp-30h]@1
  __int64 v4; // [sp+28h] [bp-28h]@4
  __int64 v5; // [sp+30h] [bp-20h]@4
  __int64 v6; // [sp+38h] [bp-18h]@4
  __int64 v7; // [sp+48h] [bp-8h]@1

  v7 = *MK_FP(__FS__, 40LL);
  bzero(&s, 0x20uLL);
  for ( i = 0; i <= 31; ++i )
  {
    *((_BYTE *)&s + i) |= *(_BYTE *)(i + a1) >> 7;
    *((_BYTE *)&s + i) |= (*(_BYTE *)(i + a1) & 0x40) >> 1;
    *((_BYTE *)&s + i) |= 2 * (*(_BYTE *)(i + a1) & 0x20);
    *((_BYTE *)&s + i) |= (*(_BYTE *)(i + a1) & 0x10) >> 3;
    *((_BYTE *)&s + i) |= 16 * (*(_BYTE *)(i + a1) & 8);
    *((_BYTE *)&s + i) |= 2 * (*(_BYTE *)(i + a1) & 4);
    *((_BYTE *)&s + i) |= 2 * (*(_BYTE *)(i + a1) & 2);
    *((_BYTE *)&s + i) |= 16 * (*(_BYTE *)(i + a1) & 1);
  }
  *(_QWORD *)a1 = s;
  *(_QWORD *)(a1 + 8) = v4;
  *(_QWORD *)(a1 + 16) = v5;
  *(_QWORD *)(a1 + 24) = v6;
  return *MK_FP(__FS__, 40LL) ^ v7;
}
```

Here we can see the key is iterated over and another key is constructed from some arithemetic applied to the key's bytes. The new key value then overwrites the old one which means we have to find the inverse of the above routine, apply it to the string "Please, may I have the flag now\0" and the result will be our second key. The above routine can be expressed as follows at byte-level:

```python
(l[i] >> 7) | ((l[i] & 0x40) >> 1) | ((l[i] & 0x20) << 1) | ((l[i] & 0x10) >> 3) | ((l[i] & 8) << 4) | ((l[i] & 4) << 1) | ((l[i] & 2) << 1) | ((l[i] & 1) << 4)
```

Which corresponds to the following invertible substitution table

```
10000000 -> 00000001
01000000 -> 00100000
00100000 -> 01000000
00010000 -> 00000010
00001000 -> 10000000
00000100 -> 00001000
00000010 -> 00000100
00000001 -> 00010000
```

Inverting the above table gives us the following expression:

```python
((l[i] & 1) << 7) | ((l[i] & 0x20) << 1) | ((l[i] & 0x40) >> 1) | ((l[i] & 2) << 3) | ((l[i] & 0x80) >> 4) | ((l[i] & 8) >> 1) | ((l[i] & 4) >> 1) | ((l[i] & 0x10) >> 4)
```

Using the above methods ([collected in this IDA python script](solution/crack_step.py)) for reversing and running [this script](solution/crack_sol.py):

```python
from pwn import *

def inv_sbox(c):
    p = ''
    for i in xrange(len(c)):
        p += chr(((ord(c[i]) & 1) << 7) | ((ord(c[i]) & 0x20) << 1) | ((ord(c[i]) & 0x40) >> 1) | ((ord(c[i]) & 2) << 3) | ((ord(c[i]) & 0x80) >> 4) | ((ord(c[i]) & 8) >> 1) | ((ord(c[i]) & 4) >> 1) | ((ord(c[i]) & 0x10) >> 4))
    return p

key1 = "RotM"
key2 = inv_sbox("Please, may I have the flag now\x00")

host = 'step_8330232df7a7e389a20dd37eb55dfc13.quals.shallweplayaga.me'
port = 2345

h = remote(host, port, timeout = None)

print h.recvuntil('Key1: ')
h.sendline(key1)
print h.recvuntil('Key2: ')
h.sendline(key2)
h.interactive()

h.close()
```

Gives us the flag:

```bash
$ python crack_sol.py 
[+] Opening connection to step_8330232df7a7e389a20dd37eb55dfc13.quals.shallweplayaga.me on port 2345: Done
Key1: 
Key2: 
[*] Switching to interactive mode
This flag is: Woah-a, woah-a, When the tears are over

[*] Got EOF while reading in interactive
```