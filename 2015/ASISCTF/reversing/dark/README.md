# ASIS CTF Quals 2015: dark

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASIS CTF Quals 2015 | dark | Reversing |    125 |

**Description:**
>*Find the flag in this [file](challenge).*

----------
## Write-up

Let's take a look at the binary:

>```bash
>file dark
>dark; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, stripped
>```

And let's take a look at the flag.enc:

>```bash
>head -c 100 flag.enc | xxd
>0000000: 7abf 5a26 4e55 7691 73b3 77ab f4ed c1b3  z.Z&NUv.s.w.....
>0000010: c2c3 a5ae 37ee 2733 4313 c514 dda5 cfdf  ....7.'3C.......
>0000020: f607 250f 171f 7337 c212 169b c269 32e7  ..%...s7.....i2.
>0000030: 3f5e 4956 5e06 eb5c bb5a 4a26 de66 5b8c  ?^IV^..\.ZJ&.f[.
>0000040: 0096 b4cf 165f 1366 67e1 978a 82ef 9207  ....._.fg.......
>0000050: 2760 072d b8a8 f257 3149 7e5c 7d63 84a3  '`.-...W1I~\}c..
>0000060: 70a1 e0ca                                p...
>```

Let's just load the binary into IDA to get a pseudocode decompilation of the main routine:

>```c
>__int64 __fastcall mainroutine(int a1, __int64 a2)
>{
>  void *v2; // rsp@3
>  void *v3; // rsp@3
>  __int64 v5; // [sp+0h] [bp-A0h]@3
>  __int64 v6; // [sp+8h] [bp-98h]@3
>  __int64 v7; // [sp+10h] [bp-90h]@1
>  int v8; // [sp+1Ch] [bp-84h]@1
>  char nptr; // [sp+20h] [bp-80h]@5
>  char v10; // [sp+21h] [bp-7Fh]@5
>  char s; // [sp+30h] [bp-70h]@5
>  char v12; // [sp+31h] [bp-6Fh]@5
>  __int64 v13; // [sp+40h] [bp-60h]@5
>  unsigned int v14; // [sp+4Ch] [bp-54h]@5
>  void *v15; // [sp+50h] [bp-50h]@3
>  __int64 v16; // [sp+58h] [bp-48h]@3
>  void *ptr; // [sp+60h] [bp-40h]@3
>  __int64 v18; // [sp+68h] [bp-38h]@3
>  int v19; // [sp+70h] [bp-30h]@3
>  int v20; // [sp+74h] [bp-2Ch]@3
>  FILE *v21; // [sp+78h] [bp-28h]@3
>  FILE *stream; // [sp+80h] [bp-20h]@3
>  int j; // [sp+88h] [bp-18h]@4
>  int i; // [sp+8Ch] [bp-14h]@3
>
>  v8 = a1;
>  v7 = a2;
>  if ( a1 == 3 )
>  {
>    stream = fopen(*(const char **)(v7 + 8), "r");
>    v21 = fopen(*(const char **)(v7 + 16), "wb");
>    v20 = 30215;
>    v19 = 16;
>    v18 = 30214LL;
>    v2 = alloca(30224LL);
>    ptr = &v5;
>    v16 = 30214LL;
>    v6 = 16LL;
>    v3 = alloca(30224LL);
>    v15 = &v5;
>    fread(&v5, 1uLL, 0x7607uLL, stream);
>    for ( i = 0; v20 / v19 > i; ++i )
>    {
>      for ( j = 0; j < v19; ++j )
>      {
>        v14 = *((_BYTE *)ptr + v19 * (i + 1) - j - 1);
>        sprintf(&s, "%02x", v14);
>        nptr = v12;
>        v10 = s;
>        v13 = strtol(&nptr, 0LL, 16);
>        *((_BYTE *)v15 + v19 * i + j) = i * i ^ j * j ^ v13;
>      }
>    }
>    fwrite(v15, 1uLL, v20, v21);
>    fclose(v21);
>    fclose(stream);
>  }
>  else
>  {
>    printf("Usage: %s inputfile outputfile\n", *(_QWORD *)v7);
>  }
>  return 0LL;
>}
>```

So we can see the binary takes two arguments: input and output filenames. It then opens the input file, reads at most 30215 bytes into a buffer, transforms them in some fashion and writes the result to the output file. Looks like a straightforward encoder with a static key embedded in the binary.

The least clear part of the encoding algorithm is the following:

>```c
>        sprintf(&s, "%02x", v14);
>        nptr = v12;
>        v10 = s;
>        v13 = strtol(&nptr, 0LL, 16);
>```

However looking at the disassembly instead of the pseucode:

>```asm
>.text:0000000000400887                 mov     edx, [rbp+var_54]
>.text:000000000040088A                 lea     rax, [rbp+s]
>.text:000000000040088E                 mov     esi, offset a02x ; "%02x"
>.text:0000000000400893                 mov     rdi, rax        ; s
>.text:0000000000400896                 mov     eax, 0
>.text:000000000040089B                 call    _sprintf
>.text:00000000004008A0                 movzx   eax, [rbp+var_6F]
>.text:00000000004008A4                 mov     [rbp+nptr], al
>.text:00000000004008A7                 movzx   eax, [rbp+s]
>.text:00000000004008AB                 mov     [rbp+var_7F], al
>.text:00000000004008AE                 lea     rax, [rbp+nptr]
>.text:00000000004008B2                 mov     edx, 10h        ; base
>.text:00000000004008B7                 mov     esi, 0          ; endptr
>.text:00000000004008BC                 mov     rdi, rax        ; nptr
>.text:00000000004008BF                 call    _strtol
>```

and the stack layout:

>```asm
>-0000000000000070 s               db ?
>-000000000000006F var_6F          db ?
>-000000000000006E                 db ? ; undefined
>(...)
>-0000000000000080 nptr            db ?
>-000000000000007F var_7F          db ?
>-000000000000007E                 db ? ; undefined
>```

Shows that it simply takes a byte, converts it to a 2-digit hexadecimal representation and swaps the hex digits before converting it back, thus effectively swapping the most and least significant bits of every byte. So the encoding algorithm effectively comes down to the following:

>```python
>src_index = 16 * (i+1) - j - 1
>dst_index = 16 * i + j
>plaintext[dst_index] = i**2 ^ j**2 ^ swap_byte(plaintext[src_index])
>```

Given that we know the index values at every point, we can simply [run the algorithm](solution/dark_descramble.py) in the reverse direction to retrieve the original plaintext:

>```python
>#!/usr/bin/python
>#
># ASIS CTF Quals 2015
># dark (REVERSING/125)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>def swap_byte(b):
>	s = '%02x' % b
>	return int(s[1]+s[0], 16)
>
>def descramble(ciphertext):
>	read_count = 30215
>	write_count = 30215
>	block_size = 16
>	reg08 = 2**8  #  8-bit registers
>	reg32 = 2**32 # 32-bit registers
>
>	ptr = list(ciphertext)
>	plaintext = [0x00]*len(ptr)
>
>	for i in xrange(len(ptr)):
>		ptr[i] = ord(ptr[i])
>
>	for i in xrange(0, write_count / block_size):
>		for j in xrange(block_size):
>			src_offset = (block_size * (i + 1) - j - 1) % reg32
>			dst_offset = (block_size * i + j) % reg32
>			plaintext[src_offset] = swap_byte(ptr[dst_offset] ^ ((i * i ^ j * j) % reg08))
>
>	return "".join(chr(x) for x in plaintext)
>
>open("flag.dec","wb").write(descramble(open("./flag.enc", "rb").read()))
>```

Which when run gives us a file [flag.dec](solution/flag.dec):

>```bash
>head -c 100 flag.dec | xxd
>0000000: 2550 4446 2d31 2e33 0a25 c4e5 f2e5 eba7  %PDF-1.3.%......
>0000010: f3a0 d0c4 c60a 3420 3020 6f62 6a0a 3c3c  ......4 0 obj.<<
>0000020: 202f 4c65 6e67 7468 2035 2030 2052 202f   /Length 5 0 R /
>0000030: 4669 6c74 6572 202f 466c 6174 6544 6563  Filter /FlateDec
>0000040: 6f64 6520 3e3e 0a73 7472 6561 6d0a 7801  ode >>.stream.x.
>0000050: b595 3d4f c330 1086 f7fc 8a1b d3a1 87e3  ..=O.0..........
>0000060: f3d7 8d20                                ...
>```

Which is simply a PDF containing the flag: ASIS{6b8dd896aaef5c60b475f92de24ca39b}