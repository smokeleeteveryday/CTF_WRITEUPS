#!/usr/bin/env python
#
# AIVD Cyber Challenge 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from z3 import *

def string_check(a1, a2):
	byte_602060 = "\x24\x5E\x77\x0B\x24\x11\x5A\x4F\x3E\x72\x41\x28\x43\x4C\x7C\x14"

	if(a2 != 16):
		return 0

	for i in xrange(0, 16):
		# modular indexes starting at different offsets within string
		index1 = (i + 3) % 16
		index2 = i % 16
		index3 = (i + 5) % 16
		index4 = (i + 11) % 16
		index5 = (i + 12) % 16

		v6 = chr(ord(a1[index1]) ^ ord(a1[index2]) ^ ord(a1[index3]) ^ ord(a1[index4]) ^ ord(a1[index5]))

		if(byte_602060[i] != v6):
			return 0

	return 1

# Convert string_check to system of linear equations and use Z3 to solve it
def solve_check():
	byte_602060 = "\x24\x5E\x77\x0B\x24\x11\x5A\x4F\x3E\x72\x41\x28\x43\x4C\x7C\x14" 

	l = []
	for i in xrange(0, 16):
		# Add unknown
		l.append(BitVec(i, 8))

	s = Solver()
	for i in xrange(0, 16):
		index1 = (i + 3) % 16
		index2 = i % 16
		index3 = (i + 5) % 16
		index4 = (i + 11) % 16
		index5 = (i + 12) % 16

		# add equation as satisfiability constraint
		s.add(l[index1] ^ l[index2] ^ l[index3] ^ l[index4] ^ l[index5] == ord(byte_602060[i]))

	# Check if problem is satisfiable before trying to solve it
	if(s.check() == sat):
		# Now solve it
		sol_model = s.model()
		# Convert solution to string
		sol = ""
		for i in xrange(0, 16):
			sol += chr(sol_model[l[i]].as_long())
		return sol
	else:
		return False

def main_routine(arg):
	v3 = len(arg) #v3 = pre_decode(arg)

	if(string_check(arg, v3)):
		print "[+]Arg: [%s] is correct! :)" % arg
	else:
		print "[-]Arg: [%s] is incorrect :(" % arg

	return

arg = solve_check()
if(arg != False):
	main_routine(arg)
else:
	print "[-]No SAT solution to system of linear equations :("