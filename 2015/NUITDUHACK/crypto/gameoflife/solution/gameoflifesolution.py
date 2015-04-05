#!/usr/bin/python
#
# Nuit Du Hack CTF 2015
# Game Of Life (CRYPTO/150) Solution
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import itertools

def xor(ent1, ent2):
    key = itertools.cycle(ent2)
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in itertools.izip(ent1, key))

f = open("cipher.txt", 'rb')
lines = f.readlines()

encfile = ''
for i in xrange(114, len(lines)):
	bitstream = '00000000'
	data = lines[i][0: len(lines[i])-1]
	encfile += xor(data, bitstream)

print encfile