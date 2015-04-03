# Backdoor CTF 2015: Rsalot

**Category:** Crypto
**Points:** 250
**Description:** 

> The flag is encrypted using a system that makes use of prime factorization of large numbers. 
>
> Decrypt the flag from [this](challenge/RSALOT.tar.gz).

## Write-up

The challenge consists of a collection of 100 RSA public keys and an RSA-encrypted flag file. Given the large number of RSA public keys we immediately suspected at least a single pair would have a moduli n with a common prime factor. This poses a problem because, given two RSA public keys (n1, e1), (n2, e2) where n1 = p\*q1 and n2 = p\*q2, we can trivially factor n1 and n2 by calculating the greatest common divisor of n1 and n2 gcd(n1, n2) = p and hence obtain the corresponding private keys [[1](https://factorable.net/faq.html)], [[2](http://www.hyperelliptic.org/tanja/vortraege/facthacks-RSA.pdf)].

We cooked up a [quick & dirty script](solution/rsalot.py) which checked all public key pairs for a common prime factor and if it found one (or more) it would try to decrypt to ciphertext with it:

>```python
>#!/usr/bin/python
>#
># Backdoor CTF 2015
># RSALOT (CRYPTO/250) Exploit
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import os
>from Crypto.PublicKey import RSA
>from Crypto.Cipher import PKCS1_OAEP
>from base64 import b64decode
>
># GCD (times sign of b if b is nonzero, times sign of a if b is zero)
>def gcd(a,b):
>	while b != 0:
>		a,b = b, a % b
>	return a
>
># Extended Greatest Common Divisor
>def egcd(a, b):
>	if (a == 0):
>		return (b, 0, 1)
>	else:
>		g, y, x = egcd(b % a, a)
>		return (g, x - (b // a) * y, y)
>
># Modular multiplicative inverse
>def modInv(a, m):
>	g, x, y = egcd(a, m)
>	if (g != 1):
>		raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
>	else:
>		return x % m
>
># Calculate private exponent from n, e, p, q
>def getPrivate(n, e, p, q):
>	d = modInv(e, (p-1)*(q-1))
>	return RSA.construct((n, e, d, p, q, ))
>
># Get prime factors of n1 if n1 and n2 have common prime factor
>def commonPrimeFactor(n1, n2):
>	p = gcd(n1, n2)
>	if((p != 1) and (p != n1) and (p != n2)):
>		q = n1 / p
>		return (p, q)		
>	else:
>		return None
>
># Import all keys
>def getKeys():
>	keys = {}
>	privKeys = []
>
>	filenames = next(os.walk("."))[2]
>	for filename in filenames:
>		if(filename[-3:] == "pem"):
>			f = open(filename, 'rb')
>			externKey = f.read()
>			f.close()
>			keys[int(filename[:-4])] = RSA.importKey(externKey)
>
>	# Check for common prime factors
>	for index1 in keys:	
>		key1 = keys[index1]
>
>		for index2 in keys:
>			if(index1 == index2):
>				continue
>			
>			key2 = keys[index2]
>			r = commonPrimeFactor(key1.n, key2.n)
>			if(r != None):
>				print "[+]Got private key from common modulus between (%d) and (%d)" % (index1, index2)
>				privKeys.append(getPrivate(key1.n, key1.e, r[0], r[1]))
>				
>	return privKeys
>
># Decrypt ciphertext using private key (PKCS1 OAEP format)
>def do_decrypt(rsakey, ciphertext):
>	rsakey = PKCS1_OAEP.new(rsakey) 
>	plaintext = rsakey.decrypt(b64decode(ciphertext)) 
>	return plaintext
>
># Get all private keys
>privKeys = getKeys()
>ciphertext = open("flag.enc", 'rb').read()
>
># Try all potential private keys we obtain
>for privKey in privKeys:
>	try:
>		print do_decrypt(privKey, ciphertext)
>		print ""
>	except:
>		pass
>```

Which gave the following result:

>```bash
>$ python rsalot.py
>[+]Got private key from common modulus between (64) and (87)
>[+]Got private key from common modulus between (87) and (64)
>the_flag_is_b767b9d1fe02eb1825de32c6dacf4c2ef78c738ab0c498013347f4ea1e95e8fa
>```