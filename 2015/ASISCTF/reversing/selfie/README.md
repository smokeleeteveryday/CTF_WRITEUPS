# ASIS CTF Quals 2015: selfie

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASIS CTF Quals 2015 | selfie | Reversing |    150 |

**Description:**
>*Find the flag in this [file](challenge/selfie).*

----------
## Write-up

See what file has to say first:

>```bash
>file selfie
>selfie; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
>```

And fetch some pseudocode:

>```c
>int __cdecl main(int argc, const char **argv, const char **envp)
>{
>  const char **v4; // [sp+0h] [bp-110h]@1
>  char v5[8]; // [sp+10h] [bp-100h]@4
>  char v6[112]; // [sp+20h] [bp-F0h]@2
>  char s[8]; // [sp+90h] [bp-80h]@1
>  int v8; // [sp+D8h] [bp-38h]@4
>  int v9; // [sp+DCh] [bp-34h]@4
>  FILE *stream; // [sp+E0h] [bp-30h]@4
>  int v11; // [sp+ECh] [bp-24h]@1
>  int v12; // [sp+F0h] [bp-20h]@1
>  unsigned int v13; // [sp+F4h] [bp-1Ch]@1
>  void *ptr; // [sp+F8h] [bp-18h]@1
>  int j; // [sp+104h] [bp-Ch]@12
>  unsigned int i; // [sp+108h] [bp-8h]@5
>  int v17; // [sp+10Ch] [bp-4h]@1
>
>  v4 = argv;
>  ptr = 0LL;
>  v13 = 0;
>  v12 = 13848;
>  strcpy(s, "ASIS{4a2cdaf7d77165eb3fdb70 : i am the first part of flag\t");
>  v11 = strlen(s);
>  v17 = 0;
>  putchar(10);
>  while ( v17 < v11 )
>  {
>    v6[v17] = s[v17];
>    v6[v17 + 1] = 0;
>    loading((__int64)v6);
>    ++v17;
>  }
>  putchar(10);
>  stream = fopen(*argv, "r");
>  fseeko(stream, 0LL, 2);
>  v13 = ftello(stream);
>  rewind(stream);
>  ptr = malloc((signed int)(v13 + 1));
>  v9 = fread(ptr, 1uLL, (signed int)v13, stream);
>  *((_BYTE *)ptr + (signed int)v13) = 0;
>  strcpy(v5, "              ");
>  v8 = strlen(v5);
>  if ( argc == 3 )
>  {
>    for ( i = 0; (signed int)i < (signed int)v13; ++i )
>    {
>      if ( *((_BYTE *)ptr + (signed int)i) == 84
>        && *((_BYTE *)ptr + (signed int)i + 1) == 114
>        && *((_BYTE *)ptr + (signed int)i + 2) == 121 )
>        printf("%d[%c]\n", i, *((_BYTE *)ptr + (signed int)i), v4);
>    }
>  }
>  for ( j = 0; j < v8; ++j )
>    v5[j] = *((_BYTE *)ptr + v12 + j);
>  puts(v5);
>  fclose(stream);
>  return 0;
>}
>```

We can see from the source the first part of the flag is slowly output to the screen, running it gives us the following:

>```bash
>$ ./selfie
>ASIS{4a2cdaf7d77165eb3fdb70 : i am the first part of flag	 
>
>Try harder :)
>```

If we look at the code we can see it also performs an fopen() on the first argument of argv, which is the filename of the file itself. It then proceeds to read its own body into memory and, after outputting the flag, output the 15 bytes located at offset 13848, which is the string "Try harder :)". This is confirmed by the (argc == 3) check which searches the binary buffer for the string "Try". Running the binary with two arbitrary commands gives us the following output:

>```bash
>$ ./selfie ayy lmao
>ASIS{4a2cdaf7d77165eb3fdb70 : i am the first part of flag	 
>
>13848[T]
>Try harder :)
>```

So if we look at this offset in a hex editor we see that the string "Try harder :)" is located amid what looks like a section table:

>```asm
>00003610   00 00 00 00 00 00 00 00  54 72 79 20 68 61 72 64           Try hard
>00003620   65 72 20 3A 29 0A 00 47  43 43 3A 20 28 44 65 62   er :)  GCC: (Deb
>00003630   69 61 6E 20 34 2E 39 2E  32 2D 31 30 29 20 34 2E   ian 4.9.2-10) 4.
>00003640   39 2E 32 00 47 43 43 3A  20 28 44 65 62 69 61 6E   9.2 GCC: (Debian
>00003650   20 34 2E 38 2E 34 2D 31  29 20 34 2E 38 2E 34 00    4.8.4-1) 4.8.4 
>00003660   00 2E 73 79 6D 74 61 62  00 2E 73 74 72 74 61 62    .symtab .strtab
>00003670   00 2E 73 68 73 74 72 74  61 62 00 2E 69 6E 74 65    .shstrtab .inte
>00003680   72 70 00 2E 6E 6F 74 65  2E 41 42 49 2D 74 61 67   rp .note.ABI-tag
>00003690   00 2E 6E 6F 74 65 2E 67  6E 75 2E 62 75 69 6C 64    .note.gnu.build
>000036A0   2D 69 64 00 2E 67 6E 75  2E 68 61 73 68 00 2E 64   -id .gnu.hash .d
>000036B0   79 6E 73 79 6D 00 2E 64  79 6E 73 74 72 00 2E 67   ynsym .dynstr .g
>000036C0   6E 75 2E 76 65 72 73 69  6F 6E 00 2E 67 6E 75 2E   nu.version .gnu.
>000036D0   76 65 72 73 69 6F 6E 5F  72 00 2E 72 65 6C 61 2E   version_r .rela.
>000036E0   64 79 6E 00 2E 72 65 6C  61 2E 70 6C 74 00 2E 69   dyn .rela.plt .i
>```

This, however, is neither were the section table is supposed to be in this ELF nor does it correspond to this ELF's section table so this made us suspicious and we looked up a little to find this:

>```asm
>00008960   7F 45 4C 46 02 01 01 00  00 00 00 00 00 00 00 00    ELF            
>00008976   02 00 3E 00 01 00 00 00  30 05 40 00 00 00 00 00     >     0 @     
>00008992   40 00 00 00 00 00 00 00  C8 1D 00 00 00 00 00 00   @       È       
>00009008   00 00 00 00 40 00 38 00  08 00 40 00 1E 00 1B 00       @ 8   @     
>00009024   06 00 00 00 05 00 00 00  40 00 00 00 00 00 00 00           @       
>```

It seems that there is another ELF binary hidden in our binary so we extract it and [take a look at it](challenge/hidden_selfie):

>```bash
>$file hidden_selfie
>hidden_selfie; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
>```

We load it into IDA to get pseudocode:

>```c
>int __cdecl main(int argc, const char **argv, const char **envp)
>{
>  signed __int64 v3; // rcx@1
>  char *v4; // rdi@1
>  signed __int64 v5; // rsi@1
>  char targetbuf[1536]; // [sp+0h] [bp-620h]@1
>  char *dest; // [sp+600h] [bp-20h]@11
>  unsigned int v9; // [sp+608h] [bp-18h]@4
>  int v10; // [sp+60Ch] [bp-14h]@4
>  __int64 timestamp; // [sp+610h] [bp-10h]@4
>  unsigned int i; // [sp+61Ch] [bp-4h]@5
>
>  v3 = 190LL;
>  v4 = targetbuf;
>  v5 = 4196736LL;
>  while ( v3 )
>  {
>    *(_QWORD *)v4 = *(_QWORD *)v5;
>    v5 += 8LL;
>    v4 += 8;
>    --v3;
>  }
>  *(_WORD *)v4 = *(_WORD *)v5;
>  timestamp = (unsigned int)time(0LL);
>  sitoor(timestamp);
>  printf("%lu %lu\n ", g_r, timestamp - g_r * g_r);
>  v10 = timestamp - g_r * g_r;
>  v9 = (unsigned __int64)((g_r - ((signed int)timestamp - (signed int)g_r * (signed int)g_r)) / 2) - 49;
>  printf("%d\n", v9);
>  if ( 3013 * g_r == 3286 * v10 + 5 )
>  {
>    for ( i = 0; (signed int)i < (signed int)v9; ++i )
>    {
>      if ( !(unsigned int)sitoor((signed int)i) )
>        putchar(targetbuf[i + 1]);
>    }
>  }
>  else
>  {
>    dest = 0LL;
>    dest = (char *)malloc(0x572uLL);
>    strcpy(dest, hidden);
>  }
>  return 0;
>}
>
>__int64 __fastcall sitoor(signed __int64 a1)
>{
>  __int64 result; // rax@2
>  signed int i; // [sp+2Ch] [bp-14h]@3
>  long double v3; // [sp+30h] [bp-10h]@3
>
>  if ( a1 * a1 == a1 )
>  {
>    result = 0LL;
>  }
>  else
>  {
>    v3 = (long double)(a1 / 2);
>    for ( i = 0; i < 1000; ++i )
>      v3 = (v3 * v3 + (long double)a1) / (v3 + v3);
>    g_r = (signed __int64)v3;
>    result = 0.0 != v3 - (long double)(signed __int64)v3;
>  }
>  return result;
>}
>```

The above code retrieves the current unix timestamp, performs some arithmetic and transformations (in the form of the sitoor function) on it and checks if the resulting values satisfy some equation:

>```c
>  v9 = (unsigned __int64)((g_r - ((signed int)timestamp - (signed int)g_r * (signed int)g_r)) / 2) - 49;
>  printf("%d\n", v9);
>  if ( 3013 * g_r == 3286 * v10 + 5 )
>```

If this is the case then the following loop iterates (with a length determined by arithmetic over the current timestamp) over a buffer embedded in the binary and decide (using the sitoor function over the loop index) whether to output the current byte or not:

>```c
>    for ( i = 0; (signed int)i < (signed int)v9; ++i )
>    {
>      if ( !(unsigned int)sitoor((signed int)i) )
>        putchar(targetbuf[i + 1]);
>    }
>```

We can see from the disassembly that the buffer in question is initialized as follows:

>```asm
>.text:00000000004006FE                 lea     rax, [rbp+targetbuf]
>.text:0000000000400705                 mov     edx, offset aUthGed
>.text:000000000040070A                 mov     ecx, 0BEh
>.text:000000000040070F                 mov     rdi, rax
>.text:0000000000400712                 mov     rsi, rdx
>.text:0000000000400715                 rep movsq
>```

and looks like this:

>```asm
>0000000000400980  93 74 68 B2 47 65 64 00  D9 EE 20 B5 9A 55 E4 62  ôth¦Ged.+e ¦ÜUSb
>0000000000400990  75 73 EC 1E A5 FA 8D 2D  9C 96 65 68 26 3D 81 59  us8.Ñ·.-£ûeh&=.Y
>00000000004009A0  10 0F 91 AA 95 63 86 C3  C0 3C C7 11 57 D9 92 AD  ..æ¬òcå++<¦.W+Æ¡
>00000000004009B0  9B 73 6F F6 FF F4 7B 57  1B FE 5A 18 A6 C2 FB 7E  ¢so÷ ({W.¦Z.ª-v~
>00000000004009C0  17 64 D3 4E BE 39 2A 0D  E9 1D 35 DA C4 03 AB A6  .d+N+9*.T.5+-.½ª
>00000000004009D0  58 08 6E 1D 73 A1 D4 B0  E7 7A 0B F0 2C A7 57 56  X.n.sí+¦tz.=,ºWV
>```

So we know our scrambled buffer consists of 0xBE QWORDS (1520 bytes) and we can simply extract the buffer and iterate over it in its entirety testing the index against a ported version of the sitoor function. This way we won't have to find out at what time we have to execute the binary in order to match the intended timestamp. The [following script](solution/selfie_descramble.py) automates the whole process:

>```python
>#!/usr/bin/python
>#
># ASIS CTF Quals 2015
># selfie (REVERSING/150)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>g_r = 0
>
># fetch hidden binary
>def get_hidden_elf(selfie):
>	data = open(selfie, "rb").read()
>	offset = 8960 # offset of hidden ELF
>	return data[offset: ]
>
># fetch scrambled buffer from hidden ELF
>def get_scrambled_buffer(hidden_selfie_buffer):
>	offset = 2432 # offset of scrambled buffer
>	size = 1521   # size of scrambled buffer
>	return hidden_selfie_buffer[offset: offset+size]
>
># ported sitoor function
>def sitoor(a):
>	global g_r
>
>	if(a*a == a):
>		return False
>
>	v3 = float(a) / 2
>	for i in xrange(1000):
>		v3 = float(v3*v3 + a) / (v3+v3)
>	g_r = long(v3)
>	return (0.0 != (v3 - float(long(v3))))
>
>def descramble(selfie):
>	scrambled = get_scrambled_buffer(get_hidden_elf(selfie))
>	#Try bruteforce approach
>	v9 = 1521
>	res = ""
>	for i in xrange(v9):
>		if not(sitoor(i)):
>			res += scrambled[i + 1]
>	return res
>
>print "[+]Got flag: [%s]" % descramble("./selfie")
>```

Which gives us the second part of the flag:

>```bash
>$ ./selfie_descramble.py
>[+]Got flag: [the secodn part of flag is: 93a641a99a}]
>```

Combined with the first part we get the flag:

>*ASIS{4a2cdaf7d77165eb3fdb7093a641a99a}*