#!/usr/bin/python
#
# PoliCTF 2015
# reversemeplz (REVERSING/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import string

def rot13(char):
	table = string.maketrans('abcdefghijklmnopqrstuvwxyz', 'nopqrstuvwxyzabcdefghijklm')
	return string.translate(char, table)

magic_table = [-1, 17, -11, 3, -8, 5, 14, -3, 1, 6, -11, 6, -8, -10, 0]

key = chr(98)
for i in magic_table:
	key += chr(ord(key[len(key)-1]) + i)

print "[+]Flag: [flag{%s}]" % rot13(key)