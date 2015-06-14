# AIVD Cyber Challenge 2015

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| AIVD Cyber Challenge 2015 | Cyber Challenge | * | - |

**Description:**
>*The Dutch General Intelligence and Security Service (AIVD) recently released a [cyber challenge](challenge_2015.zip) as part of a recruitment drive looking for cyber security specialists. Given that everybody at Smoke Leet Everyday already have successful careers as male models and we're paid handsomely by the Illuminati/NWO/Bilderberg/insertconspiracyhere we're not interested in the recruitment drive but we did have a couple of spare minutes to kill so why not.*

----------
## Write-up

# Stage 0

Unzipping the challenge archive gives us three files:

* check (a lua password check script)
* server.key (a passphrase encrypted RSA private key)
* traffic.pcap (a network capture of some traffic)



If we load up the pcap in wireshark we see several SSL/TLS encrypted sessions so our goal here is probably to decrypt the RSA private key which probably corresponds to the public key of the certificate of one of the SSL/TLS sessions. Let's take a look at the private key:

>```
>-----BEGIN RSA PRIVATE KEY-----
>Proc-Type: 4,ENCRYPTED
>DEK-Info: AES-128-CBC,0F104B1AD5DA7044656B3E5F156E1379
>
>AIkOA7QV4eWZkyOCt+TZzCbeNOVhlm425mpjaOVXLW0MXk+4+Mp1nycvWDsPNUT4
>QSYATENxHHyfnrYgQRkjI8o/5D+uXVVGeXM1GoRiz2zX5aU+D9GnPmGMh1Fq/zbA
>dt45dWvjIFMagxWsiquvE3rVVjxguL0Anlhgz51YnQnbXH57aZTNtT/AFutHC/N1
>MWaGgYybtFTw264ZiXT1efs1YjbDOaDw8AkdfmBRA4+g4p8JdWhMC0N+hIlStXlr
>0Eaxqs/zF+rjq5fX1yIj2v9zvGJDIldei3xgVBfxH3AvIxj0xEyOlBftwOLUT2Wp
>/VhsNu59tZyY1vEBYudb2DpK7i5YiKCqj+fn+JXQbKFcW6bLvLoXa1EtlJdNmQ56
>qtH6sOTRyD2x34orWX1QDdpK5OvH5ZXYys5x6kSSRS4=
>-----END RSA PRIVATE KEY-----
>```

We can see the private key is encrypted using AES (128-bit, CBC mode) with IV 0F104B1AD5DA7044656B3E5F156E1379. In order to decrypt the private key we need the AES symmetric key which can be obtained as MD5(passphrase + IV) or we can simply use:

>```bash
>openssl rsa -text -in server.key -passin 'pass:<passphrase_here>'
>```

We assume the corresponding passphrase can be derived from the lua script, let's take a look at it:

>```lua
>#!/usr/bin/lua
>
>--
>-- password checker
>--
>
>function fa( x )
>
>	return ((x + 3141592653))
>
>end
>
>function fb( x )
>
>	return ((3*x + 1732050808))
>
>end
>
>function fc( x )
>
>	return ((5*x + 2236067977))
>
>end
>
>function fd( x )
>
>	return ((7*x + 2645751311))
>
>end
>
>
>function check( input )
>
>	local t = {}
>	local fl = {}
>	local len = string.len(input)
>	local res = true
>
>	print("Let me check your password...")
>
>	if len ~= 16 then
>		print("Nope...")
>		return
>	end
>
>
>	fl[1] = fa
>	fl[2] = fb
>	fl[3] = fc
>	fl[4] = fd
>
>	for i = 0,3 do
>		t[i+1] = 16777216*string.byte(input, 4*i+1)
>		t[i+1] = t[i+1] + 65536*string.byte(input, 4*i+2)
>		t[i+1] = t[i+1] + 256*string.byte(input, 4*i+3)
>		t[i+1] = t[i+1] + string.byte(input, 4*i+4)
>	end
>
>	for j = 1,10000000 do
>		for i = 1, #t do
>			local fi = fl[(t[i] % 4)+1]
>			t[i] = fi(t[i]) % 4294967296
>		end
>	end
>
>
>	if t[1] ~= 2066590424 then
>		res = false
>	end
>
>	if t[2] ~= 4241186467 then
>		res = false
>	end
>
>	if t[3] ~= 2486763883 then
>		res = false
>	end
>
>	if t[4] ~= 2743090029 then
>		res = false
>	end
>
>	if res == true then
>		print("Congratulations!")
>	else		
>		print("Nope...")
>	end
>
>end
>
>--
>-- Main program 
>--
>
>io.write("Please enter the password: ")
>io.flush()
>pwd = io.read()
>check( pwd ) 
>```

Who knows why they decided to write this in lua but the script basically takes a 16-byte string, divides it into blocks of 4, calculates a polynomial over the ascii values:

![alt eq1](eq1.png)

and subsequently performs 10000000 iterations of the following function:

![alt eq2](eq2.png)

where:

![alt eq3](eq3.png)

Then it checks if the t of all 4 blocks equal given values. We simply decided to go for the quick route of writing a [partial brute-force based solution](solutions/check_crack.py) after inverting the above equations and simply enumerating possible solutions.

>```python
>#!/usr/bin/env python
>#
># AIVD Cyber Challenge 2015
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>import struct
>
>max_intval = 4294967296
>
>def reverse_fa( y ):
>	solutionsx = []
>	for i in xrange(0,2):
>		candidate = (((max_intval * i) + y ) - 3141592653 ) / 1
>		if candidate > 0 and (candidate % 4) == 0:
>				solutionsx.append(candidate)
>
>	return solutionsx
>
>def reverse_fb( y ):
>	solutionsx = []
>	for i in xrange(0,4):
>		candidate = (((max_intval * i) + y ) - 1732050808 )
>		if candidate % 3 != 0:
>			continue 
>
>		candidate /= 3
>
>		if candidate > 0 and (candidate % 4) == 1:
>			solutionsx.append(candidate)
>
>	return solutionsx
>
>def reverse_fc( y ):
>	solutionsx = []
>	for i in xrange(0,6):
>		candidate = (((max_intval * i) + y ) - 2236067977 ) 
>		if candidate % 5 != 0:
>			continue 
>
>		candidate /= 5
>
>		if candidate > 0 and (candidate % 4) == 2:
>				solutionsx.append(candidate)
>
>	return solutionsx
>
>def reverse_fd( y ):
>	solutionsx = []
>	for i in xrange(0,8):
>		candidate = (((max_intval * i) + y ) - 2645751311 ) 
>		if candidate % 7 != 0:
>			continue 
>
>		candidate /= 7
>
>		if candidate > 0 and (candidate % 4) == 3:
>				solutionsx.append(candidate)
>
>	return solutionsx
>
>prev_solutions = []
>
>def solve():
>	global prev_solutions
>	curr_solutions = []
>
>	for solution in prev_solutions:
>		for func in [reverse_fa, reverse_fb, reverse_fc, reverse_fd]:
>			for next_solution in func(solution):
>				if next_solution not in curr_solutions:
>					curr_solutions.append(next_solution)
>
>	prev_solutions[:] = curr_solutions
>	
>final_password = ""
>for begin_solution in [2066590424, 4241186467, 2486763883, 2743090029]:
>	
>	prev_solutions = [begin_solution]
>	print "[*] H4x1ng th3 g1bs0n: '%s'" % begin_solution
>	for i in range(1, 10000001):
>		if i % 1000000 == 0:
>			print "%d / 10 000 000 (%d %%)" % (i, (i/100000))
>
>		solve()	# we just need to call solve() 10 000 000 times
>			
>	for final_solution in prev_solutions:
>		if final_solution > max_intval:
>			break
>		final_candidate = struct.pack(">I", final_solution)
>		if final_candidate.isalnum():
>			print "[*]ayy lmao found block: %s " % final_candidate
>			final_password += final_candidate
>			print "[*]Password so far: '%s'" % final_password
>
>print "[+]PASSWORD [ %s ] " % final_password
>```

This gives us the passphrase: Grh7F1maWs9r5Ty8

Decrypting server.key gives us the following RSA private key:

>```
>-----BEGIN RSA PRIVATE KEY-----
>MIIBOgIBAAJBAOpkKFVNFsokhpUT+Iw/uB3F4VfJDEHn2l1tJ3MUQ5BkdgcUN8HR
>spof5oEBNBPc5JgkAMJk4WWqzQIWDAe3yJkCAQMCQQCcQsWOM2SGwwRjYqWy1SVp
>LpY6hggr7+bo82+iDYJgQbK3AFiaVcdyvqCg9bNTIbwVJcYQkvxvtUB1dvk5SQsj
>AiEA+CA1wdMPihAQtsPSkQAo0XgumDQDHW8Kwi0OL/S1h/cCIQDx1F3xB0F9XfE+
>y74WFwF5ADy/dYVJTxAqJNVmPRSv7wIhAKVqzoE3X7FgCySCjGCqxeD6ybrNV2j0
>sdbItB/4eQVPAiEAoTg+oK+A/j6g1IfUDroA+1V91PkDhjS1cW3jmX4Nyp8CICdx
>dBB5VUga7uM7uWPWM9KVbv8xB8PXXKmrr0Gtj8BZ
>-----END RSA PRIVATE KEY-----
>```

We can then decrypt SSL/TLS traffic from the pcap by specifying this private key in Edit -> Preferences -> Protocols -> SSL -> RSA Keys List -> New:

* IP Address: 0.0.0.0 (wildcard)
* Port: 0 (wildcard)
* Protocol: http

But since there is quite a bit SSL/TLS traffic in the pcap to different servers we first have to find out which session actually got decrypted. We can do this by looking at certificates corresponding to each session until we find a suspicious/interesting one but we figured that the server would probably be configured to use an older SSL/TLS version (and without ephemeral key usage because otherwise this excercise would be rather pointless) so we simply sorted the SSL/TLS sessions by protocol and immediately spotted a session to [5.11.111.0] with the rather dodgy certificate:

![alt cert](cert.png)

This is an obvious indicator (note that the locality is Zoetermeer where the AIVD HQ is). When looking at the decrypted session data we see the following request:

![alt packet](packet.png)

Followed by a HTTP 200 OK response from the server and an ELF binary. Navigating to the server ourselves allows us to download and inspect the binary:

# Stage 1

>```bash
>file breakme
>breakme: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=f43bbd2e693d241b83c8f1b673f4e0c8e6e9ed18, stripped
>```

It's a stripped 64-bit ELF executable. We load it up in IDA and get some pseudocode (annotated and renamed for clarity by us):

>```c
>signed __int64 __fastcall mainroutine(int a1, __int64 a2)
>{
>  signed __int64 result; // rax@2
>  signed __int64 v3; // rcx@5
>  __int64 v4; // rdi@5
>  bool v5; // zf@7
>
>  init_some_bss_stuff();                        // init some bss data
>  if ( ptrace(0, 0LL, 1LL, 0LL) == -1 )         // ptrace anti-debugging check
>  {
>    show_message(0x602300LL);
>    result = 0xFFFFFFFFLL;
>  }
>  else if ( a1 == 2 )                           // requires 1 additional command line argument, eg. ./breakme arg
>  {
>    v3 = -1LL;                                  // convoluted strlen() using repne scasb
>    v4 = *(_QWORD *)(a2 + 8);
>    do
>    {
>      if ( !v3 )
>        break;
>      v5 = *(_BYTE *)v4++ == 0;
>      --v3;
>    }
>    while ( !v5 );
>    if ( (unsigned int)string_check(*(_QWORD *)(a2 + 8), ~(_DWORD)v3 - 1) ) // check if string passes check
>    {
>      show_message(0x602440LL);
>      system_exec(*(_QWORD *)(a2 + 8));         // execute via system
>      result = 0LL;
>    }
>    else
>    {
>      show_message(0x602300LL);
>      result = 0xFFFFFFFFLL;
>    }
>  }
>  else
>  {
>    show_message(0x6024E0LL);
>    result = 0xFFFFFFFFLL;
>  }
>  return result;
>}
>
>int __fastcall system_exec(__int64 a1)
>{
>  int result; // eax@1
>  __int64 v2; // rdx@1
>  char s; // [sp+10h] [bp-60h]@1
>  __int64 v4; // [sp+68h] [bp-8h]@1
>
>  v4 = *MK_FP(__FS__, 40LL);
>  decode_string3(0x6023A0LL);
>  snprintf(&s, 0x50uLL, "%s%s", 0x6023E4LL, a1);
>  result = system(&s);
>  v2 = *MK_FP(__FS__, 40LL) ^ v4;
>  return result;
>}
>```

Looking at the above code we can quickly spot that the program:

* initializes some variables (which it decodes at runtime)
* check if it's being ptrace debugged
* checks if it has 1 command line argument
* checks if that argument passes a certain check function
* if so, it prefixes it with a decoded variable and executes the result using system()

Without having to debug the application it's a safe bet to say that system() will probably execute some bash one-liner or command to which our command-line argument is the argument. If we execute the binary we can see that incorrect execution (eg. missing or incorrect argument) will result in a fake segfault message:

>```bash
>ltrace ./breakme test
>__libc_start_main(0x400b6e, 2, 0x7fff08bc4798, 0x400c60 <unfinished ...>
>memcpy(0x602264, "ugCM\004[W/V\002\022_Ka]M\034@\002b_R]}\002kUM\023[V/"..., 51)                                                                                       = 0x602264
>memcpy(0x6024e4, "G|\305\0\364\026\022m\326\002\360G_j\204[\341MA|\323\b\343H\f", 25)                                                                                  = 0x6024e4
>memcpy(0x602304, "\227\224\363\374n\315\260\220\340\370d\315\344\227\365\344g\327", 18)                                                                                = 0x602304
>memcpy(0x602444, "\365\277\231\374Q\020\241\271\217\265[\030\366\243\214\372^\023\241\271\210\360\037\031\344\265\224\265L\003\340\252"..., 36)                        = 0x602444
>memcpy(0x6023a4, "h\367\257\343\003\237\036\376\271\234F\332V\363\265\234F\327c\004\263\325L\325R\004\257\217K\346e\0"..., 48)                                         = 0x6023a4
>ptrace(0, 0, 1, 0)                                                                                                                                                     = -1
>puts("Segmentation fault"Segmentation fault
>)                                                                                                                                             = 19
>+++ exited (status 255) +++
>```

In order to determine the correct value of the argument we will have to reverse string_check:

>```c
>signed __int64 __fastcall string_check(__int64 a1, int a2)
>{
>  signed __int64 result; // rax@2
>  char v3; // ST1F_1@4
>  char v4; // ST1F_1@4
>  unsigned __int8 v5; // ST1F_1@4
>  signed int i; // [sp+14h] [bp-10h]@3
>
>  if ( a2 == 16 )
>  {
>    for ( i = 0; i <= 15; ++i )
>    {
>      v3 = (*(_BYTE *)(a1
>                     + (signed int)(((((unsigned int)((i + 3) >> 31) >> 28) + (_BYTE)i + 3) & 0xF)
>                                  - ((unsigned int)((i + 3) >> 31) >> 28))) | *(_BYTE *)(a1
>                                                                                       + (signed int)(((((unsigned int)(i >> 31) >> 28) + (_BYTE)i) & 0xF) - ((unsigned int)(i >> 31) >> 28))))
>         - (*(_BYTE *)(a1
>                     + (signed int)(((((unsigned int)(i >> 31) >> 28) + (_BYTE)i) & 0xF)
>                                  - ((unsigned int)(i >> 31) >> 28))) & *(_BYTE *)(a1
>                                                                                 + (signed int)(((((unsigned int)((i + 3) >> 31) >> 28)
>                                                                                                + (_BYTE)i
>                                                                                                + 3) & 0xF)
>                                                                                              - ((unsigned int)((i + 3) >> 31) >> 28))));
>      v4 = (v3 | *(_BYTE *)(a1
>                          + (signed int)(((((unsigned int)((i + 5) >> 31) >> 28) + (_BYTE)i + 5) & 0xF)
>                                       - ((unsigned int)((i + 5) >> 31) >> 28))))
>         - (v3 & *(_BYTE *)(a1
>                          + (signed int)(((((unsigned int)((i + 5) >> 31) >> 28) + (_BYTE)i + 5) & 0xF)
>                                       - ((unsigned int)((i + 5) >> 31) >> 28))));
>      v5 = (v4 | *(_BYTE *)(a1
>                          + (signed int)(((((unsigned int)((i + 11) >> 31) >> 28) + (_BYTE)i + 11) & 0xF)
>                                       - ((unsigned int)((i + 11) >> 31) >> 28))))
>         - (v4 & *(_BYTE *)(a1
>                          + (signed int)(((((unsigned int)((i + 11) >> 31) >> 28) + (_BYTE)i + 11) & 0xF)
>                                       - ((unsigned int)((i + 11) >> 31) >> 28))));
>      if ( byte_602060[(signed __int64)i] != (v5 | *(_BYTE *)(a1
>                                                            + (signed int)(((((unsigned int)((i + 12) >> 31) >> 28)
>                                                                           + (_BYTE)i
>                                                                           + 12) & 0xF)
>                                                                         - ((unsigned int)((i + 12) >> 31) >> 28))))
>                                           - (v5 & *(_BYTE *)(a1
>                                                            + (signed int)(((((unsigned int)((i + 12) >> 31) >> 28)
>                                                                           + (_BYTE)i
>                                                                           + 12) & 0xF)
>                                                                         - ((unsigned int)((i + 12) >> 31) >> 28)))) )
>        return 0LL;
>    }
>    result = 1LL;
>  }
>  else
>  {
>    result = 0LL;
>  }
>  return result;
>}
>
>```

After rewriting the convoluted above statements the check can be reduced to:

* A check to see if the argument is 16 bytes long
* Followed by 15 iterations of a series of xor operations over 5 bytes the result of which is compared against a stored variable

The python equivalent can be seen in the solution below. This results in a system of 16 linear equations (using XOR) with 16 unknowns thus having exactly one unique solution which can easily be found by a theorem-prover such as [Microsoft's Z3](http://z3.codeplex.com/):

![alt eq4](eq4.png)

This gives the [solution](solution/breakme_crack.py):

>```python
>#!/usr/bin/env python
>#
># AIVD Cyber Challenge 2015
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from z3 import *
>
>def string_check(a1, a2):
>	byte_602060 = "\x24\x5E\x77\x0B\x24\x11\x5A\x4F\x3E\x72\x41\x28\x43\x4C\x7C\x14"
>
>	if(a2 != 16):
>		return 0
>
>	for i in xrange(0, 16):
>		# modular indexes starting at different offsets within string
>		index1 = (i + 3) % 16
>		index2 = i % 16
>		index3 = (i + 5) % 16
>		index4 = (i + 11) % 16
>		index5 = (i + 12) % 16
>
>		v6 = chr(ord(a1[index1]) ^ ord(a1[index2]) ^ ord(a1[index3]) ^ ord(a1[index4]) ^ ord(a1[index5]))
>
>		if(byte_602060[i] != v6):
>			return 0
>
>	return 1
>
># Convert string_check to system of linear equations and use Z3 to solve it
>def solve_check():
>	byte_602060 = "\x24\x5E\x77\x0B\x24\x11\x5A\x4F\x3E\x72\x41\x28\x43\x4C\x7C\x14" 
>
>	l = []
>	for i in xrange(0, 16):
>		# Add unknown
>		l.append(BitVec(i, 8))
>
>	s = Solver()
>	for i in xrange(0, 16):
>		index1 = (i + 3) % 16
>		index2 = i % 16
>		index3 = (i + 5) % 16
>		index4 = (i + 11) % 16
>		index5 = (i + 12) % 16
>
>		# add equation as satisfiability constraint
>		s.add(l[index1] ^ l[index2] ^ l[index3] ^ l[index4] ^ l[index5] == ord(byte_602060[i]))
>
>	# Check if problem is satisfiable before trying to solve it
>	if(s.check() == sat):
>		# Now solve it
>		sol_model = s.model()
>		# Convert solution to string
>		sol = ""
>		for i in xrange(0, 16):
>			sol += chr(sol_model[l[i]].as_long())
>		return sol
>	else:
>		return False
>
>def main_routine(arg):
>	v3 = len(arg) #v3 = pre_decode(arg)
>
>	if(string_check(arg, v3)):
>		print "[+]Arg: [%s] is correct! :)" % arg
>	else:
>		print "[-]Arg: [%s] is incorrect :(" % arg
>
>	return
>
>arg = solve_check()
>if(arg != False):
>	main_routine(arg)
>else:
>	print "[-]No SAT solution to system of linear equations :("
>```

Which gives us the password:

>```bash
>$ ./breakme_crack.py
>[+]Arg: [xvFgr231Kif09Pbv] is correct! :)
>```

Executing the application with the password as an argument results in a wget download of a file from the [5.11.111.0] server:

>```bash
>./breakme xvFgr231Kif09Pbv
>trying to download the next stage...
>https://52.11.111.0/xvFgr231Kif09Pbv
>Connecting to 52.11.111.0:443... connected.
>WARNING: cannot verify 52.11.111.0's certificate, issued by â€˜/C=NL/ST=Zuid-Holland/L=Zoetermeer/O=Baked Air Security Services/OU=Dodgy CA/CN=Dodgy SSL CAâ€™:
>  Unable to locally verify the issuer's authority.
>    WARNING: certificate common name â€˜Challengeâ€™ doesn't match requested host name â€˜52.11.111.0â€™.
>HTTP request sent, awaiting response... 200 OK
>Length: 551281 (538K)
>Saving to: â€˜xvFgr231Kif09Pbvâ€™
>
>100%[====================================================================================================================================================================================================================================>] 551,281      563KB/s   in 1.0s   
>
>xvFgr231Kif09Pbv saved [551281/551281]
>```

# Stage 2

Let's check what kind of file we have here:

>```bash
>file xvFgr231Kif09Pbv
>xvFgr231Kif09Pbv: Zip archive data, at least v2.0 to extract
>```

When unpacking it we get a pdf called [gefelicteerd.pdf](challenge/gefelicteerd.pdf) and an archive called [bonus.tar.gz](bonus.tar.gz) which is a bonus challenge. When opening the pdf (the filename means, slightly misspelled, 'congratulations' in dutch) we see some recruitment message with a 'redacted' part:

![alt gefeli](gefeli.png)

Simply copy/pasting from below the redacted part gives us:

>ZGF0IHpvdSB0ZSBtYWtrZWxpamsgemlqbg==

which is

>"dat zou te makkelijk zijn" (That would be too easy)

A red herring. So we investigate the PDF using a stream dumping tool and spot the following stream:

>```
> <<
> 	
> 	/Author (e2l2OjRmY2NmZjlmMWM5OGExNGY3MWY0M2Q1NDY1NzQ3YmMwfQ==)
> 	/Subject (e2FsZzpBRVNfT0ZCfQ==)
> 	/Title (e2tleTo0YTViNmEwZGE3MzQ1ZTY2ODAyYzNhY2YxODA4MDg0MX0=)
> >>
>```

Decoding the base64 gives us:

>```
>{iv:4fccff9f1c98a14f71f43d5465747bc0}
>{alg:AES_OFB}
>{key:4a5b6a0da7345e66802c3acf18080841}
>```

Which indicate that there is a ciphertext somewhere encrypted under AES (OFB mode) with that particular IV and key. We tried looking at different streams for potential hidden ciphertext but none of them qualified so we decided to extract the only contained image which turned out to contain the ciphertext:

![alt gefelicteerd-000.jpg](gefelicteerd-000.jpg)

[Putting it all together](gefeli_decrypt.py) allows us to decrypt the ciphertext and complete the final stage:

>```python
>#!/usr/bin/env python
>#
># AIVD Cyber Challenge 2015
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from Crypto.Cipher import AES
>
>def decrypt(ciphertext, key, iv, mode):
>	crypt = AES.new(key, mode, iv)
>	return crypt.decrypt(ciphertext)
>
>ciphertext = "313aa9be110094c2bd4479c2a278d427".decode('hex')
>iv   = "4fccff9f1c98a14f71f43d5465747bc0".decode('hex')
>key  = "4a5b6a0da7345e66802c3acf18080841".decode('hex')
>mode = AES.MODE_OFB
>
>plaintext = decrypt(ciphertext, key, iv, mode)
>print plaintext
>```

Which gives us a sUp3R s3Cr3T phone number you can call or write on toilet stalls or whatever:

>```bash
>$./gefeli_decrypt.py
>+31610702301
>```

# BONUS

As for the bonus part, [here's our write-up](BONUS.md).