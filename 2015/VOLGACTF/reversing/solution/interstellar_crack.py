#!/usr/bin/python
#
# VolgaCTF Quals 2015
# Interstellar (REVERSE/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import gmpy2

# a1 XNOR a2
def XNOR(a1, a2):
	v2 = len(a1)
	if(v2 != len(a2)):
		print "[-]len(a1) != len(a2)"
		exit()

	a3 = ""
	for i in xrange(0, len(a1)):
		if(a1[i] == a2[i]):
			v3 = chr(49)
		else:
			v3 = chr(48)

		a3 += v3
	return a3

# decimal int to bin
def dec2bin(a1):
	return format(a1, '#010b')[2:]

# interstellar crypt function
def interstellar_crypt(s):
	binarystring = "01111101001000101000000111101001001011111110010011100111010011000010101101110110100001101011100101001110000000001101000110001011011010101001000000010010001100011001100011001011010101111011110110001100101100101000110011101111101101000110110010101001100100110100010101101111101111011001100011111101"

	#__gmpz_init(&v16);
	v16 = gmpy2.mpz(0)

	for i in xrange(0, len(s)):
		#__gmpz_mul_ui(&v16, &v16, 307LL);
		v16 = gmpy2.mul(v16, 307)

		#__gmpz_add_ui(&v16, &v16, s[SHIDWORD(stat_loc.__iptr)]);
		v16 = gmpy2.add(v16, ord(s[i]))

	#LODWORD(v4) = __gmpz_get_str(0LL, 2LL, &v16);
	v4 = XNOR(v16.digits(2), binarystring)
	s1 = ""

	# Iterate over chunks of 8
	for i in xrange(0, (len(v4) >> 3)):
		v5 = chr(int(v4[8*i: (8*i)+8], 2))
		s1 += v5
	return s1

# interstellar test
def interstellar_test(s):
	s2 = "From a seed a mighty trunk may grow.\n"

	if(len(s) == 36):
		return (interstellar_crypt(s) == s2)
	else:
		return False

# interstellar recover
def interstellar_recover(s2):
	v4 = ""
	binarystring = "01111101001000101000000111101001001011111110010011100111010011000010101101110110100001101011100101001110000000001101000110001011011010101001000000010010001100011001100011001011010101111011110110001100101100101000110011101111101101000110110010101001100100110100010101101111101111011001100011111101"

	for i in xrange(0, len(s2)):
		v4 += dec2bin(ord(s2[i]))

	v16 = gmpy2.mpz(XNOR(v4, binarystring), 2)
	print "[*]P(flag) = %d" % v16

	charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-.:;<=>?@[\]^_{}"

	flag = ""
	for i in xrange(36):
		for c in charset:
			if((v16 - ord(c)) % 307 == 0):
				v16 -= ord(c)
				v16 /= 307
				flag += c
				break

	return flag[::-1]

s2 = "From a seed a mighty trunk may grow.\n"
flag = interstellar_recover(s2)
if(interstellar_test(flag)):
	print "[+]Got flag: [%s]" % flag