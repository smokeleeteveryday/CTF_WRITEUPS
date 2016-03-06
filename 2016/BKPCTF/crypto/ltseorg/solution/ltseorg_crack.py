#!/usr/bin/python
#
# BKPCTF 2016
# ltseorg (CRYPTO/4)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import binascii
from Crypto.Cipher import AES

# March-15: After 23 tries I think we fixed the issue with the IV.
IV = binascii.unhexlify("696c61686773726c7177767576646968") 

BLOCK_SIZE = 16

key1 = ["00" for x in xrange(32)]; key1[0] = "11";key1 =  binascii.unhexlify("".join(key1))
key2 = ["00" for x in xrange(32)]; key2[0] = "FF";key2 =  binascii.unhexlify("".join(key2))

P = AES.new(key1, AES.MODE_ECB)
Q = AES.new(key2, AES.MODE_ECB)

def pad_msg(msg):
	while not (len(msg) % 16 == 0): msg+="\x00"
	return msg

def xor(str1, str2):
	out = []
	for i in xrange(len(str1)):
		out.append( chr(ord(str1[i])^ord(str2[i])) )
	return "".join(out)

# "Pretty much" Grostl's provably secure compression function assuming ideal ciphers
	# Grostl pseudo-code is: h = P(m + h) + h + Q(m) and this is basically the same thing, right?
	# Ltsorg pseudo-code: h = P(m + h) + m + Q(h)
def compress(m, h): return xor( xor( P.encrypt( xor(m, h) ), m), Q.encrypt(h) ) 

def finalization(m, h): return xor(m, h)[0:14]

def hash(msg):
	msg=pad_msg(msg)
	# groestl's IV was boring 
	h = IV

	for i in xrange(0, len(msg), BLOCK_SIZE):
		m = msg[i: i+BLOCK_SIZE]
		h = compress(m ,h)
	return finalization(m, h)

def check(hashstr1, hashstr2): 
	hash1 = binascii.unhexlify(hashstr1);hash2 = binascii.unhexlify(hashstr2)
	if hashstr1 == hashstr2 or hash1 == hash2: return False 
	elif hash(hash1) == hash(hash2): return True
	return False

b0 = xor(P.decrypt(Q.encrypt(IV)), IV)
h0 = compress(b0, IV)
b1 = xor(P.decrypt(Q.encrypt(h0)), h0)

input1 = b0.encode('hex')
input2 = (b0 + b1).encode('hex')

assert check(input1, input2)

print input1
print input2