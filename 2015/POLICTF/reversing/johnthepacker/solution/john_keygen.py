#!/usr/bin/python
#
# PoliCTF 2015
# johnthepacker (REVERSING/350)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from math import floor, log
from struct import unpack

def pow_0(arg):
	a5 = float(arg)
	v5 = float(pow(a5, 5.0)) * 0.5166666688
	v6 = v5 - float(pow(a5, 4.0)) * 8.125000037
	v7 = float(pow(a5, 3.0)) * 45.83333358 + v6
	v8 = v7 - float(pow(a5, 2.0)) * 109.8750007 + a5 * 99.65000093 + 83.99999968
	return int(floor(v8))

def pow_1(arg):
	a1 = ((arg - 21) / 4)
	if(a1 == 0):
		a1 ^= 0x8000000000000000
		a1 += 9.223372036854776e18
	return int(log(a1, 2))

def key_gen():
	magic_table_0 = "\x15\x00\x00\x00\x00\x80\x00\x00\x15\x00\x00\x00\x00\x00\x08\x00\x15\x00\x00\x00\x00\x00\x80\x00\x15\x00\x00\x00\x00\x80\x00\x00\x15\x00\x00\x00\x00\x00\x40\x00\x15\x00\x00\x00\x00\x80\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x00\x00\x40\x00\x15\x00\x00\x00\x00\x00\x08\x00\x15\x00\x00\x00\x00\x00\x00\x80\x15\x00\x00\x00\x00\x80\x00\x00"
	magic_table_1 = "\x44\x07\x43\x59\x1C\x5B\x1E\x19\x47\x00"

	key = ""

	# First 6 bytes
	for i in xrange(6):
		key += chr(pow_0(i+1))

	# Next 11 bytes
	for i in xrange(11):
		index = (2 * i) * 4
		magic_value = unpack('<Q', magic_table_0[index: index + 8])[0]
		char_val = pow_1(magic_value)

		# ( !(*(_BYTE *)(a5 + 17) & 1) )
		if((i == 6) and (char_val & 1 == 0)):
			# Wrap-around compensation
			char_val -= 1
		
		key += chr(char_val)

	# Final 10 bytes
	for i in xrange(10):
		key += chr(ord(key[len(key)-1]) ^ ord(magic_table_1[i]))

	return key

print "[+]Flag: [flag{%s}]" % key_gen()