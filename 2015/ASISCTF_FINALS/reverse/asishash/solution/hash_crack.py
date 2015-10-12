#!/usr/bin/env python
#
# ASISCTF Finals 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

def hashf(s):
    # Multiplier
    M = 0x21
    # Initial state
    state = 0x1505
    for c in s:
        state = ((state * M) + (ord(c) ^ 0x8F))
    return state

def recover_m(h):
	charset = "0123456789abcdef"

	M = 0x21
	I = hashf("ASIS{")
	s = "}"

	h -= (ord("}") ^ 0x8F)
	h /= M

	while (h > I):
		for c in charset:
			if ((h - (ord(c) ^ 0x8F)) % M == 0):
				s += c
				h -= (ord(c) ^ 0x8F)
				h /= M

	s += "{SISA"

	return s[::-1]

h = 27221558106229772521592198788202006619458470800161007384471764
print recover_m(h)