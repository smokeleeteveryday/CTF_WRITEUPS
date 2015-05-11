#!/usr/bin/python
#
# ASIS CTF Quals 2015
# selfie (REVERSING/150)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

g_r = 0

# fetch hidden binary
def get_hidden_elf(selfie):
	data = open(selfie, "rb").read()
	offset = 8960 # offset of hidden ELF
	return data[offset: ]

# fetch scrambled buffer from hidden ELF
def get_scrambled_buffer(hidden_selfie_buffer):
	offset = 2432 # offset of scrambled buffer
	size = 1521   # size of scrambled buffer
	return hidden_selfie_buffer[offset: offset+size]

# ported sitoor function
def sitoor(a):
	global g_r

	if(a*a == a):
		return False

	v3 = float(a) / 2
	for i in xrange(1000):
		v3 = float(v3*v3 + a) / (v3+v3)
	g_r = long(v3)
	return (0.0 != (v3 - float(long(v3))))

def descramble(selfie):
	scrambled = get_scrambled_buffer(get_hidden_elf(selfie))
	#Try bruteforce approach
	v9 = 1521
	res = ""
	for i in xrange(v9):
		if not(sitoor(i)):
			res += scrambled[i + 1]
	return res

print "[+]Got flag: [%s]" % descramble("./selfie")