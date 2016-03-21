#!/usr/bin/python
#
# BCTF 2016
# sif (REVERSING/350)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import hashlib
from struct import pack, unpack

def magic_step(x):
	A = 0x5DEECE66D
	B = 0xB
	M = ((1 << 48) - 1)
	return (((x * A) + B) & M)

class magic:
	def __init__(self, seed):
		self.x = seed
		return

	def step(self):
		old_x = self.x
		self.x = magic_step(self.x)
		return old_x

def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def recover_mana(keystream_slice):
	assert (len(keystream_slice) == 4)
	mana_lsbs = [ord(x) for x in list(keystream_slice)]
	return ((mana_lsbs[0] << 40) | (mana_lsbs[1] << 32) | (mana_lsbs[2] << 24) | (mana_lsbs[3] << 16))

def decrypt(ciphertext, seed):
	plaintext = ''
	pos = 0
	m = magic(seed)
	for i in xrange(len(ciphertext)):
		if (pos == 0):
			rk = m.step()
			cur = [(rk >> 40), (rk >> 32), (rk >> 24), (rk >> 16)]
		plaintext += chr(ord(ciphertext[i]) ^ (cur[pos] & 0xFF))
		pos = ((pos + 1) & 3)
	return plaintext

def mana_check(mana1, mana2):
	i = 0
	print "[*] Checking mana..."
	while(i < 2**16):
		candidate = (mana1 | i)
		if ((magic_step(candidate) & 0xFFFFFFFF0000) == (mana2 & 0xFFFFFFFF0000)):
			return candidate

		i += 1

	raise Exception("[-] Couldn't check LCG outputs...")
	return

ciphertext = open('flag.png', 'rb').read()
known_png_header = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
crypto_header = ciphertext[0:8]
cipher_png_header = ciphertext[8:8+len(known_png_header)]
keystream = xor_strings(cipher_png_header, known_png_header)

print "[+] crypto header: [%s]" % (crypto_header.encode('hex'))
print "[+] derived keystream: [%s]" % (keystream.encode('hex'))

mana1 = recover_mana(keystream[0:4])
mana2 = recover_mana(keystream[4:8])

print "[+] recovered (partial) LCG output 1: [%s]" % ('{:012x}'.format(mana1))
print "[+] recovered (partial) LCG output 2: [%s]" % ('{:012x}'.format(mana2))

seed = mana_check(mana1, mana2)

print "[+] cracked LCG seed: [%s]" % ('{:08x}'.format(seed))

open('plaintext_flag.png', 'wb').write(decrypt(ciphertext[8:], seed))
print "[+] decrypted flag.png!"