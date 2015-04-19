#!/usr/bin/python
#
# Plaid CTF 2015
# Strength (CRYPTO/110)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

# GCD (times sign of b if b is nonzero, times sign of a if b is zero)
def gcd(a,b):
  while b != 0:
      a,b = b, a % b
  return a

# Extended Greatest Common Divisor
def egcd(a, b):
  if (a == 0):
      return (b, 0, 1)
  else:
      g, y, x = egcd(b % a, a)
      return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
  g, x, y = egcd(a, m)
  if (g != 1):
      raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
  else:
      return x % m

def to_bytes(n, length, endianess='big'):
   h = '%x' % n
   s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
   return s if endianess == 'big' else s[::-1]

crypt_tups = []
lines = open("captured", "rb").read().split("\n")
lines = lines[1:len(lines)-1] # get rid of first and last line
for line in lines:
	tups = line[1:len(line)-1].split(":")
	N, e, c = [long(x.strip(),16) for x in tups]
	crypt_tups.append((N, e, c))

for i in xrange(len(crypt_tups)):
	for j in xrange(len(crypt_tups)):
		if(i == j):
			continue

		N1, e1, c1 = crypt_tups[i]
		N2, e2, c2 = crypt_tups[j]

		assert (N1 == N2)

		#a1*e1 + a2*e2 = 1
		if (gcd(e1, e2) == 1):
			#a = a1 % e2
			a = modInv(e1, e2)
			#b = (gcd(e1, e2)-(a*e1))/e2 (will be negative)
			b = long((float(gcd(e1, e2)-(a*e1)))/float(e2))

			assert (b < 0)

			# Modular multiplicative inverse
			c2i = modInv(c2, N1)
			c1a = pow(c1, a, N1)
			c2b = pow(c2i, long(-b), N1)
			m = (c1a * c2b) % N1

			print to_bytes(m, 16)
			exit()