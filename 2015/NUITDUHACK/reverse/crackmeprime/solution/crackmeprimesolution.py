#!/usr/bin/python
#
# Nuit Du Hack CTF 2015
# Crackme Prime (REVERSING/150) Solution
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
from pyprimes import *

def isValidSerial(v16, v17, v18, v19, v20, v15):
	v8 = (isprime(v16) and (isprime(v17) and (isprime(v18) and (isprime(v19) and isprime(v20))))) and isprime(v15)
	return isprime((v17 + v18 + v19 + v20 + v16) % v15)

def keygen(startPoint):	
	primeiterator = primes_above(startPoint)
	p = next(primeiterator)
	
	# Generate valid prime
	while('0' in hex(p)[2:]):
		p = next(primeiterator)

	# Use as first v17,v18,v19,v20,v15 only bruteforce v16
	A = [p]*6
	while not(isValidSerial(A[0], A[1], A[2], A[3], A[4], A[5])):
		A[0] = next(primeiterator)

		while('0' in hex(A[0])[2:]):
			A[0] = next(primeiterator)

	return "-".join(hex(A[i])[2:] for i in range(6))

print keygen(0x2AD0)