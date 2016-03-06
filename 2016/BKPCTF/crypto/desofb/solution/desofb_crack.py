#!/usr/bin/python
#
# BKPCTF 2016
# desofb (CRYPTO/2)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import string
from Crypto.Cipher import DES

def is_printable(s):
	return all(c in (string.printable) for c in s)

def get_blocks(data, block_size):
	return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

c = open("ciphertext", "rb").read()
IV = '13245678'
bs = DES.block_size

assert (len(c) % bs == 0), "[-] Ciphertext not a multiple of DES blocksize"

blocks = get_blocks(c, bs)

"""
for b in blocks:
	x = xor_strings(b, IV)
	if (is_printable(x)):
		print x
"""

p = " be, tha"
k = xor_strings(blocks[2], p)

s = ""
for i in xrange(len(blocks)):
	if (i % 2 == 0):
		b = xor_strings(blocks[i], k)
	else:
		b = xor_strings(blocks[i], IV)

	s += b

print s