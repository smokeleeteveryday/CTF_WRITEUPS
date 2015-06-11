#!/usr/bin/env python
#
# AIVD Cyber Challenge 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from Crypto.Cipher import AES

def decrypt(ciphertext, key, iv, mode):
	crypt = AES.new(key, mode, iv)
	return crypt.decrypt(ciphertext)

ciphertext = "313aa9be110094c2bd4479c2a278d427".decode('hex')
iv   = "4fccff9f1c98a14f71f43d5465747bc0".decode('hex')
key  = "4a5b6a0da7345e66802c3acf18080841".decode('hex')
mode = AES.MODE_OFB

plaintext = decrypt(ciphertext, key, iv, mode)
print plaintext