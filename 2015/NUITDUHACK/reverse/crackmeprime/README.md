# Backdoor CTF 2015: Crackme Prime

**Category:** Reversing
**Points:** 150
**Description:** 

> "I am Optimus Prime, and I send this message to any surviving Autobots taking refuge among the stars. We are here, we are waiting."
>
> [Keygen me](challenge/prime.tar.gz), I'm the Prime.
> 
> Validate your serial here : http://crackmeprime.challs.nuitduhack.com/

## Write-up

The challenge consists of reversing a binary in order to write a keygen (or at least find a single valid serial) for it. As usual we start by checking our file:

>```bash
>$ file ./crackme
> crackme: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=0x92d632c664b683dc98873fe1c785d1e6928e7272, not stripped
>```

A statically linked unstripped 32-bit ELF binary it is. The next thing to do is loading it in IDA Pro and decompiling the main routine and the functions it calls:

>```c
>int __cdecl main(int argc, const char **argv, const char **envp)
>{
>  int result; // eax@6
>  signed int v4; // esi@7
>  int v5; // esi@7
>  int v6; // esi@7
>  int v7; // esi@7
>  int v8; // esi@7
>  char v9; // [sp+0h] [bp-4Eh]@7
>  char v10; // [sp+5h] [bp-49h]@7
>  char v11; // [sp+Ah] [bp-44h]@7
>  char v12; // [sp+Fh] [bp-3Fh]@7
>  char dest; // [sp+14h] [bp-3Ah]@7
>  char s; // [sp+19h] [bp-35h]@7
>  int v15; // [sp+1Eh] [bp-30h]@7
>  int v16; // [sp+22h] [bp-2Ch]@7
>  int v17; // [sp+26h] [bp-28h]@7
>  int v18; // [sp+2Ah] [bp-24h]@7
>  int v19; // [sp+2Eh] [bp-20h]@7
>  int v20; // [sp+32h] [bp-1Ch]@7
>  int *v21; // [sp+46h] [bp-8h]@1
>
>  v21 = &argc;
>  if ( argc <= 1 )
>  {
>    puts("please give me serial number");
>    exit(0);
>  }
>  if ( strlen(argv[1]) == 29 )
>  {
>    if ( strchr(argv[1], 48) )
>    {
>      puts("Invalid char");
>      result = 1;
>    }
>    else
>    {
>      memset(&s, 0, 5u);
>      memset(&dest, 0, 5u);
>      memset(&v12, 0, 5u);
>      memset(&v11, 0, 5u);
>      memset(&v10, 0, 5u);
>      memset(&v9, 0, 5u);
>      strncpy(&s, argv[1], 4u);
>      strncpy(&dest, argv[1] + 5, 4u);
>      strncpy(&v12, argv[1] + 10, 4u);
>      strncpy(&v11, argv[1] + 15, 4u);
>      strncpy(&v10, argv[1] + 20, 4u);
>      strncpy(&v9, argv[1] + 25, 4u);
>      v20 = strtol(&s, 0, 16);
>      v19 = strtol(&dest, 0, 16);
>      v18 = strtol(&v12, 0, 16);
>      v17 = strtol(&v11, 0, 16);
>      v16 = strtol(&v10, 0, 16);
>      v15 = strtol(&v9, 0, 16);
>      v4 = c1(v20);
>      v5 = c1(v19) & v4;
>      v6 = c1(v18) & v5;
>      v7 = c1(v17) & v6;
>      v8 = c1(v16) & v7;
>      result = v8 & c1(v15);
>      if ( result )
>      {
>        result = c1((v17 + v18 + v19 + v20 + v16) % v15);
>        if ( result )
>        {
>          puts("Well done !!!");
>          result = printf("%s is good serial\n", argv[1]);
>        }
>      }
>    }
>  }
>  else
>  {
>    puts("Wrong format");
>    result = 1;
>  }
>  return result;
>}
>```

From these lines:

>```c
>  if ( strlen(argv[1]) == 29 )
>  {
>    if ( strchr(argv[1], 48) )
>    {
>      puts("Invalid char");
>      result = 1;
>    }
>```

We know the serial is supposed to be 29 characters long and cannot contain the '0' character. The series of strncpy calls tells us the serial gets seperated into 6 4-digit values which get converted to a long from hex representation. This gives us the following serial format:

> XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

Where X is [1-9A-F].

Next we see a series of calls to c1 with the various serial segments as arguments resulting in the following validation check:

>```c
> v8 = (c1(v16) & (c1(v17) & (c1(v18) & (c1(v19) & c1(v20)))))
> result = v8 & c1(v15)
> if ( result )
> {
> 	result = c1((v17 + v18 + v19 + v20 + v16) % v15);
>   if ( result )
>   {
>   	puts("Well done !!!");
>       result = printf("%s is good serial\n", argv[1]);
>   }
> }
>```

Let's look at the c1 function:

>```c
>signed int __cdecl c1(int a1)
>{
>  signed int result; // eax@2
>  int v2; // [sp+0h] [bp-138h]@3
>  int v3; // [sp+4h] [bp-134h]@1
>  int v4; // [sp+8h] [bp-130h]@1
>  char v5; // [sp+Ch] [bp-12Ch]@1
>  char v6; // [sp+98h] [bp-A0h]@1
>  int (__cdecl *v7)(int); // [sp+124h] [bp-14h]@3
>  int v8; // [sp+128h] [bp-10h]@1
>  int v9; // [sp+12Ch] [bp-Ch]@1
>
>  v3 = 12345;
>  v4 = 54321;
>  v9 = (int)"azertyuiopazerty";
>  v8 = 16;
>  if ( aes_init("azertyuiopazerty", 16, &v3, &v6, &v5) )
>  {
>    result = -1;
>  }
>  else
>  {
>    v2 = 96;
>    v7 = (int (__cdecl *)(int))aes_decrypt(&v5, &buf_0, &v2);
>    EVP_CIPHER_CTX_cleanup(&v6);
>    EVP_CIPHER_CTX_cleanup(&v5);
>    result = v7(a1) != 0;
>  }
>  return result;
>}
>```

The function decrypts a static buffer using openssl_AES with the key "azertyuiopazerty" and salt 12345 and subsequently calls that 'hidden' function over a1 and returns the result.
Let's put a breakpoint after the buffer gets decrypted:

>```bash
>gdb-peda$ b *0x08048D9C
>gdb-peda$ r
>(.. we see v7 = 0x082234b0 ..)
>gdb-peda$ disas 0x082234b0, 0x8223510
>Dump of assembler code from 0x82234b0 to 0x8223510:
>```
>```asm
>=> 0x082234b0:	push   ebp
>   0x082234b1:	mov    ebp,esp
>   0x082234b3:	sub    esp,0x10
>   0x082234b6:	mov    DWORD PTR [ebp-0x8],0x0
>   0x082234bd:	mov    DWORD PTR [ebp-0x4],0x1
>   0x082234c4:	jmp    0x82234e3
>   0x082234c6:	mov    eax,DWORD PTR [ebp+0x8]
>   0x082234c9:	cdq    
>   0x082234ca:	idiv   DWORD PTR [ebp-0x4]
>   0x082234cd:	mov    eax,edx
>   0x082234cf:	test   eax,eax
>   0x082234d1:	jne    0x82234df
>   0x082234d3:	add    DWORD PTR [ebp-0x8],0x1
>   0x082234d7:	cmp    DWORD PTR [ebp-0x8],0x2
>   0x082234db:	jle    0x82234df
>   0x082234dd:	jmp    0x82234eb
>   0x082234df:	add    DWORD PTR [ebp-0x4],0x1
>   0x082234e3:	mov    eax,DWORD PTR [ebp-0x4]
>   0x082234e6:	cmp    eax,DWORD PTR [ebp+0x8]
>   0x082234e9:	jle    0x82234c6
>   0x082234eb:	cmp    DWORD PTR [ebp-0x8],0x2
>   0x082234ef:	jne    0x82234f8
>   0x082234f1:	mov    eax,0x1
>   0x082234f6:	jmp    0x82234fd
>   0x082234f8:	mov    eax,0x0
>   0x082234fd:	leave  
>   0x082234fe:	ret 
>```

Manually translating this disassembly listing to pseudo-code yields:

>```c
>function v7(a1)
>{
>	var1 = 0
>	var2 = 1
>	while(var2 <= a1)
>	{
>		if(a1 % var2 == 0)
>		{
>			var1++
>			if(var1 > 2)
>				break;
>		}
>		var2++
>	}
>	if(var1 != 2)
>	{
>		return 0;
>	}
>	else
>	{
>		return 1;
>	}
>}
>```

Which is effectively a prime-number check that returns 1 if a1 is prime and 0 if it isn't.
This means that we now know our serial should look as follows:

> X0-X1-X2-X3-X4-X5

Where every Xi is a 4-digit prime number (in hex representation) without containing zeros and in addition (sum(A1..A5) % A6) is prime too. We wrote a [little keygen](solution/crackmeprimesolution.py) to generate valid serials. It works by finding a valid prime and using it for all but 1 of the first 5 fields and for the last field. In this fashion we only have to bruteforce one of the first 5 fields so that its addition to the sum of the others will leave a remainder (modulo the found prime) that is itself prime:

>```python
>#!/usr/bin/python
>#
># Nuit Du Hack CTF 2015
># Crackme Prime (REVERSING/150) Solution
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>from pyprimes import *
>
>def isValidSerial(v16, v17, v18, v19, v20, v15):
>	v8 = (isprime(v16) and (isprime(v17) and (isprime(v18) and (isprime(v19) and isprime(v20))))) and isprime(v15)
>	return isprime((v17 + v18 + v19 + v20 + v16) % v15)
>
>def keygen(startPoint):	
>	primeiterator = primes_above(startPoint)
>	p = next(primeiterator)
>	
>	# Generate valid prime
>	while('0' in hex(p)[2:]):
>		p = next(primeiterator)
>
>	# Use as first v17,v18,v19,v20,v15 only bruteforce v16
>	A = [p]*6
>	while not(isValidSerial(A[0], A[1], A[2], A[3], A[4], A[5])):
>		A[0] = next(primeiterator)
>
>		while('0' in hex(A[0])[2:]):
>			A[0] = next(primeiterator)
>
>	return "-".join(hex(A[i])[2:] for i in range(6))
>
>print keygen(0x2AD0)
>```

Which gives us the following result:

>```bash
>$ python crackmeprimesolution.py
> 55d9-2add-2add-2add-2add-2add
>$ ./crackme 55d9-2add-2add-2add-2add-2add
> Well done !!!
> 55d9-2add-2add-2add-2add-2add is good serial
>```

Submitting the serial to the online validator gives us the flag:

> Congratulation! The flag is : WowThatWasEasyAES