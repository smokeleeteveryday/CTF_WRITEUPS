# ASIS CTF Quals 2015: tera

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASIS CTF Quals 2015 | tera | Reversing |    100 |

**Description:**
>*Be patient and find the flag in this [file](challenge/tera).*

----------
## Write-up

Let's take a look at the binary:

>```bash
>file tera
>tera; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, stripped
>```

And get a pseudocode decompilation of its main routine (with some variables renamed for clarity):

>```c
>__int64 __usercall mainroutine@<rax>(unsigned int a1@<ebx>)
>{
>  signed __int64 v1; // rsi@1
>  __int64 *v2; // rdi@1
>  signed __int64 i; // rcx@1
>  signed __int64 v4; // rcx@4
>  char *v5; // rdi@4
>  signed __int64 v6; // rsi@4
>  signed __int64 v7; // rcx@10
>  char *v8; // rdi@10
>  void *v9; // rax@16
>  signed __int64 v10; // rsi@17
>  int *v11; // rdi@17
>  signed __int64 l; // rcx@17
>  signed int v13; // eax@21
>  void *v14; // rsp@22
>  size_t v16; // [sp+0h] [bp-2350h]@22
>  __int64 v17; // [sp+8h] [bp-2348h]@22
>  int key_table[40]; // [sp+10h] [bp-2340h]@17
>  char filename[10]; // [sp+B0h] [bp-22A0h]@14
>  char v20; // [sp+BAh] [bp-2296h]@16
>  char v21; // [sp+10B0h] [bp-12A0h]@10
>  char v22; // [sp+10B1h] [bp-129Fh]@13
>  char v23; // [sp+10B3h] [bp-129Dh]@13
>  char v24; // [sp+10B5h] [bp-129Bh]@13
>  char v25; // [sp+10B7h] [bp-1299h]@13
>  char v26; // [sp+10B9h] [bp-1297h]@13
>  char v27; // [sp+10BBh] [bp-1295h]@13
>  char v28; // [sp+10BDh] [bp-1293h]@13
>  char v29; // [sp+10BFh] [bp-1291h]@13
>  char v30; // [sp+10C1h] [bp-128Fh]@13
>  char v31; // [sp+10C3h] [bp-128Dh]@13
>  char v32; // [sp+10C5h] [bp-128Bh]@13
>  char v33[80]; // [sp+20B0h] [bp-2A0h]@8
>  char v34[144]; // [sp+2100h] [bp-250h]@4
>  __int64 index_table[39]; // [sp+2190h] [bp-1C0h]@1
>  pthread_t newthread; // [sp+22C8h] [bp-88h]@20
>  void *buffer; // [sp+22D0h] [bp-80h]@22
>  size_t v38; // [sp+22D8h] [bp-78h]@22
>  FILE *v39; // [sp+22E0h] [bp-70h]@22
>  int v40; // [sp+22ECh] [bp-64h]@22
>  int v41; // [sp+22F0h] [bp-60h]@22
>  int v42; // [sp+22F4h] [bp-5Ch]@22
>  int v43; // [sp+22F8h] [bp-58h]@22
>  int v44; // [sp+22FCh] [bp-54h]@20
>  FILE *stream; // [sp+2300h] [bp-50h]@20
>  void *arg; // [sp+2308h] [bp-48h]@16
>  int v47; // [sp+2314h] [bp-3Ch]@4
>  size_t n; // [sp+2318h] [bp-38h]@1
>  __int64 m; // [sp+2320h] [bp-30h]@22
>  int k; // [sp+2328h] [bp-28h]@13
>  int j; // [sp+232Ch] [bp-24h]@7
>
>  n = 0x1F40001809E0LL;
>  v1 = 0x401480LL;
>  v2 = index_table;
>  for ( i = 38LL; i; --i )
>  {
>    *v2 = *(_QWORD *)v1;
>    v1 += 8LL;
>    ++v2;
>  }
>  v47 = 38;
>  v4 = 16LL;
>  v5 = v34;
>  v6 = 4199872LL;
>  while ( v4 )
>  {
>    *(_QWORD *)v5 = *(_QWORD *)v6;
>    v6 += 8LL;
>    v5 += 8;
>    --v4;
>  }
>  *(_WORD *)v5 = *(_WORD *)v6;
>  v5[2] = *(_BYTE *)(v6 + 2);
>  setbuf(stdout, 0LL);
>  for ( j = 0; j <= 64; ++j )
>    v33[j] = v34[2 * j];
>  v7 = 512LL;
>  v8 = &v21;
>  while ( v7 )
>  {
>    *(_QWORD *)v8 = 0LL;
>    v8 += 8;
>    --v7;
>  }
>  v22 = 47;
>  v23 = 116;
>  v24 = 109;
>  v25 = 112;
>  v26 = 47;
>  v27 = 46;
>  v28 = 116;
>  v29 = 101;
>  v30 = 114;
>  v31 = 97;
>  v32 = 10;
>  for ( k = 0; k <= 9; ++k )
>    filename[k] = *(&v21 + 2 * k + 1);
>  v20 = 0;
>  LODWORD(v9) = curl_easy_init(v8, 0LL);
>  arg = v9;
>  if ( !v9 )
>  {
>    puts("Please check your connection :)");
>LABEL_29:
>    return 0;
>  }
>  puts("Please wait until my job be done ");
>  v10 = 4200064LL;
>  v11 = key_table;
>  for ( l = 19LL; l; --l )
>  {
>    *(_QWORD *)v11 = *(_QWORD *)v10;
>    v10 += 8LL;
>    v11 += 2;
>  }
>  stream = fopen(filename, "wb");
>  v44 = pthread_create(&newthread, 0LL, (void *(*)(void *))start_routine, arg);
>  if ( v44 )
>  {
>    fprintf(_bss_start, "Error - pthread_create() return code: %d\n", (unsigned int)v44);
>    a1 = 0;
>    v13 = 0;
>  }
>  else
>  {
>    v43 = 10002;
>    curl_easy_setopt(arg, 10002LL, v33);
>    v42 = 20011;
>    curl_easy_setopt(arg, 20011LL, 4197590LL);
>    v41 = 10001;
>    curl_easy_setopt(arg, 10001LL, stream);
>    v40 = curl_easy_perform(arg);
>    curl_easy_cleanup(arg);
>    fclose(stream);
>    v39 = fopen(filename, "r");
>    v38 = n - 1;
>    v16 = n;
>    v17 = 0LL;
>    v14 = alloca(16 * ((n + 15) / 0x10));
>    buffer = &v16;
>    fread(&v16, 1uLL, n, v39);
>    for ( m = 0LL; v47 > m; ++m )
>      printf("%c\n", (unsigned int)(char)(*((_BYTE *)buffer + index_table[m]) ^ LOBYTE(key_table[m])));
>    fclose(v39);
>    v13 = 1;
>  }
>  if ( v13 == 1 )
>    goto LABEL_29;
>  return a1;
>}
>```

Ok so it looks like the binary uses curl to download some file, read its contents to a buffer and xor certain elements of that buffer with bytes from a key table. It's not clear from the pseudocode but in the disassembly we can see what file it tries to download:

>```asm
>.text:0000000000400F53                 mov     [rbp+var_3C], 26h
>.text:0000000000400F5A                 lea     rax, [rbp+var_250]
>.text:0000000000400F61                 mov     edx, offset aHttpDarksky_sl ; "http://darksky.slac.stanford.edu/simula"...
>.text:0000000000400F66                 mov     ecx, 10h
>.text:0000000000400F6B                 mov     rdi, rax
>.text:0000000000400F6E                 mov     rsi, rdx
>```

The URL is in unicode:

>```asm
>.rodata:00000000004015C0 aHttpDarksky_sl:                        ; DATA XREF: mainroutine+48o
>.rodata:00000000004015C0                 unicode 0, <http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_>
>.rodata:00000000004015C0                 unicode 0, <a_1.0000>
>.rodata:00000000004015C0                 dw 0Ah, 0
>.rodata:0000000000401646                 align 40h
>```

If we look at the directory of the file in question, however, we can see that it is roughly 31TB:

>*ds14_a_1.0000	19-Apr-2014 16:47	31T*

Since we have neither the time nor the disk space to download it in full we will use the fact that we can specify [content ranges](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html) in our HTTP header to only fetch a single byte at the offsets we require. So all we need to emulate the functionality of the binary without downloading the file are the index and key tables which get initialized from the addresses v1 = 0x401480 and v10 = 0x401680 respectively so we can simply extract them from the binary using IDA's built-in hex viewer and produce the [following decoder](solution/tera_decoder.py):

>```python
>#!/usr/bin/python
>#
># ASIS CTF Quals 2015
># tera (REVERSING/100)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from struct import unpack
>import urllib2
>
># Fetch single byte from URL using content range
>def get_buffer_byte(url, offset):
>  req = urllib2.Request(url)
>  req.headers['Range'] = 'bytes=%s-%s' % (offset, offset)
>  f = urllib2.urlopen(req)
>  return f.read()
>
># Decryption functionality
>def decrypt(url, index_table, key_table):
>	plaintext = ""
>	for m in xrange(0, 38):
>		i = unpack('<Q', index_table[m*8: (m+1)*8])[0]
>		b = get_buffer_byte(url, i)
>		k = unpack('<I', key_table[m*4: (m+1)*4])[0]
>		plaintext += chr(ord(b) ^ k)
>	return plaintext
>
># Target URL
>url = "http://darksky.slac.stanford.edu/simulations/ds14_a/ds14_a_1.0000"
>
># Key and indexing tables
>key_table = "\xF2\x00\x00\x00\x9A\x00\x00\x00\x83\x00\x00\x00\x12\x00\x00\x00\x39\x00\x00\x00\x45\x00\x00\x00\xE7\x00\x00\x00\xF4\x00\x00\x00\x6F\x00\x00\x00\xA1\x00\x00\x00\x06\x00\x00\x00\xE7\x00\x00\x00\x95\x00\x00\x00\xF3\x00\x00\x00\x90\x00\x00\x00\xF2\x00\x00\x00\xF0\x00\x00\x00\x6B\x00\x00\x00\x33\x00\x00\x00\xE3\x00\x00\x00\xA8\x00\x00\x00\x78\x00\x00\x00\x37\x00\x00\x00\xD5\x00\x00\x00\x44\x00\x00\x00\x39\x00\x00\x00\x61\x00\x00\x00\x8A\x00\x00\x00\xFB\x00\x00\x00\x22\x00\x00\x00\xFA\x00\x00\x00\x9E\x00\x00\x00\xE7\x00\x00\x00\x11\x00\x00\x00\x39\x00\x00\x00\xA6\x00\x00\x00\xF3\x00\x00\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x59\x40"
>index_table = "\xF4\x7C\x61\x89\x4C\x00\x00\x00\x83\x5F\xE9\xB5\xB4\x00\x00\x00\x6B\x68\x8D\x59\xE4\x00\x00\x00\xEF\x74\x26\xA6\x36\x01\x00\x00\xB7\xBE\x65\x7A\x83\x01\x00\x00\x7C\x46\x31\xA8\x9F\x01\x00\x00\x01\xCD\x2A\x20\xA6\x02\x00\x00\x5E\x64\x10\x3F\x49\x04\x00\x00\xE4\x65\x6D\xCE\xCD\x04\x00\x00\x7E\xDE\xC8\x8E\x02\x05\x00\x00\x56\x4A\x50\x19\x62\x05\x00\x00\xB8\x1D\x19\x2D\xBD\x05\x00\x00\x92\x25\xD0\xD5\x2B\x07\x00\x00\xFE\x04\x6D\xEE\x3D\x07\x00\x00\x20\xE3\xAF\xE5\x25\x0A\x00\x00\x9E\xFB\x64\xB4\x73\x0A\x00\x00\x4B\xE3\xF6\x59\x62\x0B\x00\x00\xDC\x94\x50\xA4\x9A\x0B\x00\x00\x39\xEA\xE0\x48\xC5\x0B\x00\x00\x56\xCC\x1E\xC4\x7A\x0C\x00\x00\x8B\xFB\x73\xF0\x85\x0C\x00\x00\x16\x91\x6A\x53\x92\x0C\x00\x00\xBF\xDA\xE6\x0B\x93\x0D\x00\x00\x40\xDA\x89\xB9\x61\x0E\x00\x00\x68\xA2\x9C\x99\x37\x0F\x00\x00\x1F\x9D\x9B\xC5\xB7\x0F\x00\x00\x9D\x93\xA3\xD3\x18\x10\x00\x00\x69\x03\xED\x2A\x20\x10\x00\x00\xF3\x6C\x92\xFB\xE8\x10\x00\x00\x65\xA0\x8E\xC3\x3B\x11\x00\x00\x4F\x04\x04\x75\x25\x13\x00\x00\x3C\xDC\x12\x06\xFB\x14\x00\x00\x92\xDA\x70\x23\x57\x16\x00\x00\x41\x44\x63\x75\x3D\x17\x00\x00\x74\x93\x2D\x0F\x9D\x1B\x00\x00\x8E\x2D\xE4\x0D\xA9\x1B\x00\x00\x3E\x8F\x4C\xEF\xE9\x1B\x00\x00\x00\x4E\xB8\xA4\xFD\x1B\x00\x00"
>
>print "[+]Got flag: [%s]" % decrypt(url, index_table, key_table)
>```

Which produces the following output:

>```bash
>$ ./tera_decoder.py
>[+]Got flag: [ASIS{3149ad5d3629581b17279cc889222b93}]
>```