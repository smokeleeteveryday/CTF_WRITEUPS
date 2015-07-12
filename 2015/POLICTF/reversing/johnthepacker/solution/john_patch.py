#!/usr/bin/python
#
# PoliCTF 2015
# johnthepacker (REVERSING/350)
#
# IDA decryption plugin
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

areas = [(0x08048AA5, 83, 0x04030201),
		(0x08048655, 17, 0x40302010),
		(0x0804869A, 17, 0x04030201),
		(0x080486DE, 23, 0x44414544),
		(0x08048A42, 24, 0x40302010),
		(0x080489A9, 38, 0x44414544),
		(0x0804890B, 39, 0x04030201),
		(0x080488E4, 9, 0x40302010),
		(0x0804873A, 54, 0x04030201),
		(0x08048813, 52, 0x42303042)]

for loc, size, key in areas:
	for i in range(size):
		d = Dword(loc+(i*4))                  
		decoded_dword = d ^ key          
		PatchDword(loc+(i*4), decoded_dword)