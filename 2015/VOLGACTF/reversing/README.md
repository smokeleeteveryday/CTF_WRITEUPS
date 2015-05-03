# VolgaCTF Quals 2015: Interstellar

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| VolgaCTF Quals 2015 | Interstellar | Reversing |    200 |

**Description:**
>*interstellar*

>*Just a small binary from a far-far galaxy*

>*[interstellar](challenge/interstellar)*

----------
## Write-up
### Reversing

We start by taking a look at the binary:

>```bash
>$ file interstellar 
> interstellar: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=7114541e8a3f2ef2ad4e972720b47f4a2ac46f14, stripped
>```

Let's load it into IDA and get some pseudocode:

>```c
>__int64 __fastcall mainroutine(int a1, __int64 a2)
>{
>  int v2; // eax@7
>  size_t v3; // rbx@15
>  char *v4; // rax@16
>  char v5; // al@17
>  size_t v6; // rbx@18
>  __int64 v8; // [sp+0h] [bp-90h]@4
>  __WAIT_STATUS stat_loc; // [sp+18h] [bp-78h]@10
>  int i; // [sp+20h] [bp-70h]@16
>  int v11; // [sp+24h] [bp-6Ch]@4
>  int v12; // [sp+28h] [bp-68h]@5
>  int v13; // [sp+2Ch] [bp-64h]@5
>  char *s; // [sp+30h] [bp-60h]@12
>  char *v15; // [sp+38h] [bp-58h]@16
>  char v16; // [sp+40h] [bp-50h]@13
>  char s1[40]; // [sp+50h] [bp-40h]@17
>  __int64 v18; // [sp+78h] [bp-18h]@1
>
>  v18 = *MK_FP(__FS__, 40LL);
>  if ( a1 != 2 )
>  {
>    puts("You should give me the flag as command-line parameter!");
>    exit(0);
>  }
>  prctl(1499557217, -1LL, 0LL, 0LL, 0LL, a2);
>  v11 = fork();
>  if ( !v11 )
>  {
>    v12 = getppid();
>    v13 = ptrace(PTRACE_ATTACH, (unsigned int)v12, 0LL, 0LL);
>    sleep(1u);
>    ptrace(PTRACE_DETACH, (unsigned int)v12, 0LL, 0LL);
>    v2 = v13 || getenv("LD_PRELOAD");
>    exit(v2);
>  }
>  wait((__WAIT_STATUS)&stat_loc);
>  if ( (_DWORD)stat_loc.__uptr )
>    exit(0);
>  s = *(char **)(v8 + 8);
>  if ( strlen(s) == 36 )
>  {
>    __gmpz_init(&v16);
>    for ( HIDWORD(stat_loc.__iptr) = 0; ; ++HIDWORD(stat_loc.__iptr) )
>    {
>      v3 = SHIDWORD(stat_loc.__iptr);
>      if ( v3 >= strlen(s) )
>        break;
>      __gmpz_mul_ui(&v16, &v16, 307LL);
>      __gmpz_add_ui(&v16, &v16, s[SHIDWORD(stat_loc.__iptr)]);
>    }
>    LODWORD(v4) = __gmpz_get_str(0LL, 2LL, &v16);
>    v15 = v4;
>    __gmpz_clear(&v16);
>    sub_400B5D(v15, binarystring);
>    for ( i = 0; ; ++i )
>    {
>      v6 = i;
>      if ( v6 >= strlen(v15) >> 3 )
>        break;
>      v5 = sub_400C02((__int64)&v15[8 * i]);
>      s1[i] = v5;
>    }
>    if ( !strcmp(s1, s2) )
>      puts("Success! You've found the right flag!");
>  }
>  return *MK_FP(__FS__, 40LL) ^ v18;
>}
>```

The above main routine consists of doing some anti-debugging stuff and requesting the flag as a command line parameter. This is followed by checking if the length of the command line parameter s is 36 and subsequently running s through a polynomial defined as follows (using functions from the GNU MP library to handle multiprecision integers):

![alt eq](eq.png)

This value is then converted to a binary string representation:

>```
>LODWORD(v4) = __gmpz_get_str(0LL, 2LL, &v16);
>```

Next we encounter two subroutines: sub_400B5D and sub_400C02. Let's take a look at them:

>```c
>size_t __fastcall sub_400B5D(const char *a1, const char *a2)
>{
>  size_t v2; // rbx@1
>  char v3; // al@5
>  size_t result; // rax@8
>  int i; // [sp+1Ch] [bp-14h]@3
>
>  v2 = strlen(a1);
>  if ( v2 != strlen(a2) )
>    exit(0);
>  for ( i = 0; ; ++i )
>  {
>    result = strlen(a1);
>    if ( i >= result )
>      break;
>    if ( a1[i] == a2[i] )
>      v3 = 49;
>    else
>      v3 = 48;
>    a1[i] = v3;
>  }
>  return result;
>}
>```

The above function compares two strings and if characters at corresponding offsets match it sets the character at that offset in the first string to '1' and else it sets it to '0'. This is effectively an XNOR over two binary string representations. The mainroutine calls XNOR over the binary representation of polynomial evaluation of our flag input and a static binary representation string stored in the binary.

>```c
>__int64 __fastcall sub_400C02(__int64 a1)
>{
>  unsigned __int8 v2; // [sp+13h] [bp-5h]@1
>  signed int i; // [sp+14h] [bp-4h]@1
>
>  v2 = 0;
>  for ( i = 0; i <= 7; ++i )
>    v2 = *(_BYTE *)(i + a1) + 2 * v2 - 48;
>  return v2;
>}
>```

This function iterates over 8 bytes in buffer a1 and calculates the recurrent expression:

![alt eq2](eq2.png)

Which effectively converts an 8-byte binary representation string to the corresponding decimal integer.

After this is done a final comparison is made by the main routine:

>```c
>    if ( !strcmp(s1, s2) )
>      puts("Success! You've found the right flag!");
>```

It compares the final result of the calculations with the statically stored string:

>```asm
>.data:00000000006020C0 s2 dq offset aFromASeedAMigh
>.data:00000000006020C0    ; DATA XREF: mainroutine+229r
>.data:00000000006020C0    ; "From a seed a mighty trunk may grow.\n"
>```

Putting this all together allows us to port the functionality to the following, more readable, python equivalent:

>```python
>def interstellar_crypt(s):
>	binarystring = "01111101001000101000000111101001001011111110010011100111010011000010101101110110100001101011100101001110000000001101000110001011011010101001000000010010001100011001100011001011010101111011110110001100101100101000110011101111101101000110110010101001100100110100010101101111101111011001100011111101"
>
>	#__gmpz_init(&v16);
>	v16 = gmpy2.mpz(0)
>
>	for i in xrange(0, len(s)):
>		#__gmpz_mul_ui(&v16, &v16, 307LL);
>		v16 = gmpy2.mul(v16, 307)
>
>		#__gmpz_add_ui(&v16, &v16, s[SHIDWORD(stat_loc.__iptr)]);
>		v16 = gmpy2.add(v16, ord(s[i]))
>
>	#LODWORD(v4) = __gmpz_get_str(0LL, 2LL, &v16);
>	v4 = XNOR(v16.digits(2), binarystring)
>	s1 = ""
>
>	# Iterate over chunks of 8
>	for i in xrange(0, (len(v4) >> 3)):
>		v5 = chr(int(v4[8*i: (8*i)+8], 2))
>		s1 += v5
>	return s1
>```

### Cracking

Obtaining the flag consists of finding the seed corresponding to the string "From a seed a mighty trunk may grow.\n" which is done by inverting the above function yielding:

>```python
>def interstellar_recover(s2):
>	v4 = ""
>	binarystring = "01111101001000101000000111101001001011111110010011100111010011000010101101110110100001101011100101001110000000001101000110001011011010101001000000010010001100011001100011001011010101111011110110001100101100101000110011101111101101000110110010101001100100110100010101101111101111011001100011111101"
>
>	for i in xrange(0, len(s2)):
>		v4 += dec2bin(ord(s2[i]))
>
>	v16 = gmpy2.mpz(XNOR(v4, binarystring), 2)
>	print "[*]P(flag) = %d" % v16
>```

We know that the, for lack of a better word, 'seed sum' can be defined as follows:

![alt eq3](eq3.png)

Hence, working in reverse direction, if we subtract the correct character from the 'seed sum' it should be congruent to 0 modulo 307. Subsequently dividing what remains after subtraction by 307 allows us to apply this process iteratively to recover the entire seed:

>```python
>	charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-.:;<=>?@[\]^_{}"
>
>	flag = ""
>	for i in xrange(36):
>		for c in charset:
>			if((v16 - ord(c)) % 307 == 0):
>				v16 -= ord(c)
>				v16 /= 307
>				flag += c
>				break
>
>	return flag[::-1]
>```

The [final script](solution/interstellar_crack.py) gives us the following output:

>```bash
>$ ./ interstellar_crack.py
>[*]P(flag) = 97815454071720498577150051643786987589437346798376099957766553517855134069080048023193864
>[+]Got flag: [W@ke_up_@nd_s0lv3_an0ther_ch@113nge!]
>```