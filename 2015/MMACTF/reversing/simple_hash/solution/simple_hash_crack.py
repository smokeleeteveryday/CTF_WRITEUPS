#!/usr/bin/env python
#
# MMACTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import string

# Alphanumeric alphabet (ordered by ASCII value)
charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Recursive version of hash function (as reversed)
def hashf(inp):
	# Multiplier
	M = 0x241
	# Modulus
	P = 0x38D7EA4C68025
	# Initial state
	state = 0
	for c in inp:
		state = ((state * M) + ord(c)) % P
	return state

# Fetches candidate characters for a given position
def index_candidate_chars(target, candidate, index):
	global charset

	r = []

	# Start out with lowest ASCII value
	tmp_candidate = list(candidate)
	tmp_candidate[index] = charset[0]
	tmp_candidate = "".join(tmp_candidate)
	p_hash = hashf(tmp_candidate)

	# Work through entire character set
	for j in xrange(1, len(charset)):
		tmp_candidate = list(tmp_candidate)
		tmp_candidate[index] = charset[j]
		tmp_candidate = "".join(tmp_candidate)
		n_hash = hashf(tmp_candidate)
		
		# Have we found it?
		if(n_hash == target):
			print "[+]Cracked input: [%s] (0x%x)" % (tmp_candidate, n_hash)
			exit()

		# If the target is in between the previous and current hash value we consider the previous character a candidate for this position
		if ((p_hash < target) and (target < n_hash)):
			r.append(charset[j-1])

		p_hash = n_hash

	return r + [charset[len(charset)-1]]

# Recursive cracking function
def crack(target, candidate, index):
	global charset

	if (index >= len(candidate)):
		return

	chars = index_candidate_chars(target, candidate, index)

	# Branch out over all candidate characters at this position
	for c in chars:
		tmp_candidate = list(candidate)
		tmp_candidate[index] = c
		tmp_candidate = "".join(tmp_candidate)
		crack(target, tmp_candidate, index + 1)

	return

# Target hash
h = 0x1E1EAB437EEB0

# Try different lengths
min_len = 6
max_len = 12

for i in xrange(min_len, max_len+1):
	print "[*]Trying length %d..." % i
	# Initial candidate (lowest cumulative value)
	candidate = charset[0]*i
	crack(h, candidate, 0)