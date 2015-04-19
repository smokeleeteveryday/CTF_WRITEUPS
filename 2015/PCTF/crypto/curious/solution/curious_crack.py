#!/usr/bin/python
#
# Plaid CTF 2015
# Curious (CRYPTO/70)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import math

def number_of_bits(n):
	return int(math.log(n, 2)) + 1

def isqrt(n):
	if n < 0:
		raise ValueError('[-]Square root not defined for negative numbers')    
	if n == 0:
		return 0
		
	a, b = divmod(number_of_bits(n), 2)
	x = 2**(a+b)

	while True:
		y = (x + n//x)//2
		if y >= x:
			return x
		x = y

def perfectSquare(n):
	h = n & 0xF    
	if h > 9:
		return -1

	if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
		t = isqrt(n)
		if (t*t == n):
			return t
		else:
			return -1    
	return -1

# Fraction p/q as continued fraction
def contfrac(p, q):
	while q:
		n = p // q
		yield n
		q, p = p - q*n, q

# Convergents from continued fraction
def convergents(cf):
	p, q, r, s = 1, 0, 0, 1
	for c in cf:
		p, q, r, s = c*p+r, c*q+s, p, q
		yield p, q

# Wiener's attack ported from https://github.com/pablocelayes/rsa-wiener-attack
def wienerAttack(n, e):
	cts = convergents(contfrac(e, n))    
	for (k, d) in cts:   
		# check if d is actually the key
		if ((k != 0) and ((e*d - 1) % k == 0)):
			phi = ((e*d - 1)//k)
			s = n - phi + 1
			# check if the equation x^2 - s*x + n = 0
			# has integer roots
			discr = s*s - 4*n
			if(discr >= 0):
				t = perfectSquare(discr)
				if ((t != -1) and ((s+t) % 2 == 0)):
					return d
	return None

def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

crypt_tups = []
lines = open("captured", "rb").read().split("\n")
lines = lines[1:len(lines)-1] # get rid of first and last line
for line in lines:
	tups = line[1:len(line)-1].split(":")
	n, e, c = [long(x.strip(),16) for x in tups]
	nsize = number_of_bits(n)
	esize = number_of_bits(e)
	# Totally unjustified heuristic
	if(abs(nsize - esize) < (nsize/16)):
		d = wienerAttack(n, e)
		if(d):
			m = pow(c, d, n)
			print to_bytes(m, 16)
			exit()