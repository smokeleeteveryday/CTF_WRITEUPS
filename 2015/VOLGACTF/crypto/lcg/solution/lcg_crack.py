#!/usr/bin/python
#
# VolgaCTF Quals 2015
# lcg (CRYPTO/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import struct

# Extended Greatest Common Divisor
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

M = 65521
class LCG():
	def __init__(self, s, a=None, b=None, state=None):
		self.m = M
		if((a != None) and (b != None) and (state != None)):
			(self.a, self.b, self.state) = (a, b, state)
		else:
			(self.a, self.b, self.state) = struct.unpack('<3H', s[:6])

	def getvars(self):
		return self.a, self.b

	def round(self):
		self.state = (self.a*self.state + self.b) % self.m
		return self.state

	def generate_gamma(self, length):
		n = (length + 1) / 2
		gamma = ''
		for i in xrange(n):
			gamma += struct.pack('<H', self.round())
		return gamma[:length]

# PNG header
knownplaintext = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"

with open('flag.png.bin', 'rb') as f:
	ciphertext = f.read()

# Recovered keystream
recgamma = ''.join([chr(d ^ c) for d,c in zip(map(ord, knownplaintext), map(ord, ciphertext))])

print "[+]Recovered keystream: [%s]" % recgamma.encode('hex')

# Recovered states
states = {}
# Only need at most 3 equations
for i in xrange(0, min(4, len(recgamma)/2)):
	# Take endian-ness into account
	state = recgamma[(2*i): (2*i)+2]
	states[i] = struct.unpack('<H', state)[0]

# subtract eq. 0 from 1 and 2
x = states[2]-states[1]
alpha = states[1]-states[0]

y = states[3]-states[1]
beta = states[2]-states[0]

# recover a, b
g, p, q = egcd(alpha, M)
g2, p2, q2 = egcd(beta, M)

if(g == 1):
	mod_inv = p % M
	a = (x * mod_inv) % M
elif(g2 == 1):
	mod_inv = p2 % M
	a = x * mod_inv % M
else:
	print "[-]No modular multiplicative inverse found :("
	exit()

b = states[i]-(states[i-1]*a) % M
# inverse of a
g, p, q = egcd(a, M)
a_inv = p
init_state = (((states[0]-b)%M)*a_inv)%M

# Recover LCG
print "[+]Recovered LCG(a=%d, b=%d, init=%d)" % (a, b, init_state)

lcg = LCG("", a=a, b=b, state=init_state)
gamma = lcg.generate_gamma(len(ciphertext))
decrypted = ''.join([chr(d ^ g)  for d,g in zip(map(ord, ciphertext), map(ord, gamma))])

f = open('flag.png','wb')
f.write(decrypted)
f.close()

print "[+]Done!"