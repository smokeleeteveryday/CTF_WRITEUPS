#!/usr/bin/env python
#
# ASISCTF Finals 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from z3 import *

def gen_license():
	filelen = 34
	filename = "_a\nb\tc_"

	f = open(filename, "wb")
	content = ""

	x = ["iKWoZL", "Vc4LTy", "GrCRed", "PhfEni", "hgyGxW"]

	s = Solver()

	lines = [None]*(5*10 + 6)
	for i in xrange(5):
		for j in xrange(6):
			lines[(i*10)+j] = BitVec((i*10)+j, 8)

	for j in xrange(6):
		s.add(lines[(0*10)+j] ^ lines[(1*10)+j] == ord(x[0][j]))
		s.add(lines[(1*10)+j] ^ lines[(3*10)+j] ^ 0x23 == ord(x[1][j]))
		s.add(lines[(3*10)+j] ^ lines[(2*10)+j] == ord(x[2][j]))
		s.add(lines[(3*10)+j] ^ lines[(4*10)+j] ^ lines[(2*10)+j] ^ 0x23 == ord(x[3][j]))
		s.add(lines[(3*10)+j] == ord(x[4][j]))

	linez = []

	# Check if problem is satisfiable before trying to solve it
	if(s.check() == sat):
		print "[+] Problem satisfiable, generating license :)"
		sol_model = s.model()
		for i in xrange(5):
			s = ""
			for j in xrange(6):
				s += chr(sol_model[lines[(i*10)+j]].as_long())

			linez.append(s)
	else:
		raise Exception("[-] Problem unsatisfiable, could not generate license :(")

	content += linez[0] + chr(10)
	content += linez[1] + chr(10)
	content += linez[2] + chr(10)
	content += linez[3] + chr(10)
	content += linez[4]

	assert(len(content) == filelen)

	f.write(content)
	f.close()

	return

gen_license()