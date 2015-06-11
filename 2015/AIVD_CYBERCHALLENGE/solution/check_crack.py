#!/usr/bin/env python
#
# AIVD Cyber Challenge 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
import struct

max_intval = 4294967296

def reverse_fa( y ):
	solutionsx = []
	for i in xrange(0,2):
		candidate = (((max_intval * i) + y ) - 3141592653 ) / 1
		if candidate > 0 and (candidate % 4) == 0:
				solutionsx.append(candidate)

	return solutionsx

def reverse_fb( y ):
	solutionsx = []
	for i in xrange(0,4):
		candidate = (((max_intval * i) + y ) - 1732050808 )
		if candidate % 3 != 0:
			continue 

		candidate /= 3

		if candidate > 0 and (candidate % 4) == 1:
			solutionsx.append(candidate)

	return solutionsx

def reverse_fc( y ):
	solutionsx = []
	for i in xrange(0,6):
		candidate = (((max_intval * i) + y ) - 2236067977 ) 
		if candidate % 5 != 0:
			continue 

		candidate /= 5

		if candidate > 0 and (candidate % 4) == 2:
				solutionsx.append(candidate)

	return solutionsx

def reverse_fd( y ):
	solutionsx = []
	for i in xrange(0,8):
		candidate = (((max_intval * i) + y ) - 2645751311 ) 
		if candidate % 7 != 0:
			continue 

		candidate /= 7

		if candidate > 0 and (candidate % 4) == 3:
				solutionsx.append(candidate)

	return solutionsx

prev_solutions = []

def solve():
	global prev_solutions
	curr_solutions = []

	for solution in prev_solutions:
		for func in [reverse_fa, reverse_fb, reverse_fc, reverse_fd]:
			for next_solution in func(solution):
				if next_solution not in curr_solutions:
					curr_solutions.append(next_solution)

	prev_solutions[:] = curr_solutions
	
final_password = ""
for begin_solution in [2066590424, 4241186467, 2486763883, 2743090029]:
	
	prev_solutions = [begin_solution]
	print "[*] H4x1ng th3 g1bs0n: '%s'" % begin_solution
	for i in range(1, 10000001):
		if i % 1000000 == 0:
			print "%d / 10 000 000 (%d %%)" % (i, (i/100000))

		solve()	# we just need to call solve() 10 000 000 times
			
	for final_solution in prev_solutions:
		if final_solution > max_intval:
			break
		final_candidate = struct.pack(">I", final_solution)
		if final_candidate.isalnum():
			print "[*]ayy lmao found block: %s " % final_candidate
			final_password += final_candidate
			print "[*]Password so far: '%s'" % final_password

print "[+]PASSWORD [ %s ] " % final_password