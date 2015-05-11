#!/usr/bin/python
#
# ASIS CTF Quals 2015
# dark (REVERSING/125)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

def swap_byte(b):
	s = '%02x' % b
	return int(s[1]+s[0], 16)

def descramble(ciphertext):
	read_count = 30215
	write_count = 30215
	block_size = 16
	reg08 = 2**8  #  8-bit registers
	reg32 = 2**32 # 32-bit registers

	ptr = list(ciphertext)
	plaintext = [0x00]*len(ptr)

	for i in xrange(len(ptr)):
		ptr[i] = ord(ptr[i])

	for i in xrange(0, write_count / block_size):
		for j in xrange(block_size):
			src_offset = (block_size * (i + 1) - j - 1) % reg32
			dst_offset = (block_size * i + j) % reg32
			plaintext[src_offset] = swap_byte(ptr[dst_offset] ^ ((i * i ^ j * j) % reg08))

	return "".join(chr(x) for x in plaintext)

open("flag.dec","wb").write(descramble(open("./flag.enc", "rb").read()))