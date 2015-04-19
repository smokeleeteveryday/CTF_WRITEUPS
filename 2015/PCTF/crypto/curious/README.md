# Plaid CTF 2015: Curious

**Category:** Crypto
**Points:** 70
**Description:** 

>The curious case of the random e.
>
>We've [captured](challenge/captured) the flag encrypted several times... do you think you can recover it?

## Write-up

The challenge consists of a file containing a collection of tuples:

>{N : e : c}
>{0xfd2066554e7f2005082570ddf50e535f956679bf5611a11eb1734268ffe32eb0f2fc0f105dd117d9d739767f300918a67dd97f52a3985483aca8aa54998a5c475842a16f2a022a3f5c389a70faeaf0500fa2d906537802ee2088a83f068aba828cc24cc83acc74f04b59a0764de7b64c82f469db4fecd71876eb6021090c7981L : 0xa23ac312c144ce829c251457b81d60171161655744b2755af9b2bd6b70923456a02116b54136e848eb19756c89c4c46f229926a48d5ac030415ef40f3ea185446fa15b5b5f11f2ec2f0f971394e285054182d77490dc2e7352d7e9f72ce25793a154939721b6a2fa176087125ee4f0c3fb6ec7a9fdb15510c97bd3783e998719L : 0x593c561db9a04917e6992328d1ecadf22aefe0741e5d9abbbc12d5b6f9485a1f3f1bb7c010b19907fe7bdecb7dbc2d6f5e9b350270002e23bd7ae2b298e06ada5f4caa1f5233f33969075c5c2798a98dd2fd57646ad906797b9e1ce77194791d3d0b097de31f135ba2dc7323deb5c1adabcf625d97a7bd84cdf96417f05269f4L}
>(...)

The first line gives us a hint about the encryption scheme as the parameters N, e and c are usually used to denote the modulus, public exponent and ciphertext in RSA.
Looking at the tuples what immediately stands out is the size of the public exponents (which are usually one of the fermat primes) which hints at the possibility for [Wiener's attack](http://en.wikipedia.org/wiki/Wiener%27s_attack) (sometimes a large public exponent is an indication of a small private exponent). Iterating over the tuples and checking each for potential vulnerability to Wiener's attack eventually [proves successful](solution/curious_crack.py):

>```python
>#!/usr/bin/python
>#
># Plaid CTF 2015
># Curious (CRYPTO/70)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import math
>
>def number_of_bits(n):
>	return int(math.log(n, 2)) + 1
>
>def isqrt(n):
>	if n < 0:
>		raise ValueError('[-]Square root not defined for negative numbers')    
>	if n == 0:
>		return 0
>		
>	a, b = divmod(number_of_bits(n), 2)
>	x = 2**(a+b)
>
>	while True:
>		y = (x + n//x)//2
>		if y >= x:
>			return x
>		x = y
>
>def perfectSquare(n):
>	h = n & 0xF    
>	if h > 9:
>		return -1
>
>	if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
>		t = isqrt(n)
>		if (t*t == n):
>			return t
>		else:
>			return -1    
>	return -1
>
># Fraction p/q as continued fraction
>def contfrac(p, q):
>	while q:
>		n = p // q
>		yield n
>		q, p = p - q*n, q
>
># Convergents from continued fraction
>def convergents(cf):
>	p, q, r, s = 1, 0, 0, 1
>	for c in cf:
>		p, q, r, s = c*p+r, c*q+s, p, q
>		yield p, q
>
># Wiener's attack ported from https://github.com/pablocelayes/rsa-wiener-attack
>def wienerAttack(n, e):
>	cts = convergents(contfrac(e, n))    
>	for (k, d) in cts:   
>		# check if d is actually the key
>		if ((k != 0) and ((e*d - 1) % k == 0)):
>			phi = ((e*d - 1)//k)
>			s = n - phi + 1
>			# check if the equation x^2 - s*x + n = 0
>			# has integer roots
>			discr = s*s - 4*n
>			if(discr >= 0):
>				t = perfectSquare(discr)
>				if ((t != -1) and ((s+t) % 2 == 0)):
>					return d
>	return None
>
>def to_bytes(n, length, endianess='big'):
>    h = '%x' % n
>    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
>    return s if endianess == 'big' else s[::-1]
>
>crypt_tups = []
>lines = open("captured", "rb").read().split("\n")
>lines = lines[1:len(lines)-1] # get rid of first and last line
>for line in lines:
>	tups = line[1:len(line)-1].split(":")
>	n, e, c = [long(x.strip(),16) for x in tups]
>	nsize = number_of_bits(n)
>	esize = number_of_bits(e)
>	# Totally unjustified heuristic
>	if(abs(nsize - esize) < (nsize/16)):
>		d = wienerAttack(n, e)
>		if(d):
>			m = pow(c, d, n)
>			print to_bytes(m, 16)
>			exit()
>```

Which gives us:

>```bash
>$ python curious_crack.py
>flag_S0Y0UKN0WW13N3R$4TT4CK!
>```