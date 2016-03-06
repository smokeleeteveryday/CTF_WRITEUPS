#!/usr/bin/python
#
# BKPCTF 2016
# unholy (REVERSING/4)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import xtea
from z3 import *
from struct import unpack, pack

def get_blocks(data, block_size):
	return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def solve_matrix_system():
	s = Solver()

	Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]
	n = [[5034563854941868,252734795015555591,55088063485350767967],[-2770438152229037,142904135684288795,-33469734302639376803],[-3633507310795117,195138776204250759,-34639402662163370450]]
	A = [0,0,0,0,0,0,0,0,0]

	X = [[BitVec(0,32), BitVec(1,32), BitVec(2,32)], [BitVec(3,32), BitVec(4,32), BitVec(5,32)], [BitVec(6,32), BitVec(7,32), BitVec(8,32)]]

	for i in xrange(3):
		for j in xrange(len(Y[0])):
			s.add(n[i][j] == ((X[i][0]*Y[0][j]) + (X[i][1]*Y[1][j]) + (X[i][2]*Y[2][j])))

	if (s.check() == sat):
		print "[*] Matrix problem satisfiable, solving..."
		sol_model = s.model()
		R = [[0,0,0], [0,0,0], [0,0,0]]
		for i in xrange(3):
			for j in xrange(3):
				R[i][j] = sol_model[X[i][j]].as_long()
		return R
	else:
		print "[-] Matrix problem unsatisfiable :("
		return []

def xtea_decrypt_matrix(matrix):
	# whatsgoingonhere
	key = [0x74616877, 0x696F6773, 0x6E6F676E, 0x65726568]
	k = ''.join([pack('>I', x) for x in key])

	m = []

	# convert python matrix
	for i in xrange(3):
		for j in xrange(3):
			m.append(matrix[i][j])

	# last ciphertext block used for validation
	m.append(0x4DE3F9FD)
	# known plaintext last block for validation
	kp = pack('<I', 0x61735320)

	c = ''.join([pack('>I', x) for x in m])
	cipher = xtea.new(k, mode=xtea.MODE_ECB)
	p1 = cipher.decrypt(c)

	# reorder blocks
	blocks = get_blocks(p1, 4)
	p1 = ''.join([b[::-1] for b in blocks])

	# validate plaintext
	if(p1[-len(kp):] == kp):
		return p1
	else:
		return ''

matrix = solve_matrix_system()
print "[+] Matrix solution:", matrix
p = xtea_decrypt_matrix(matrix)
if (p != ''):
	print "[+] Found correct plaintext: [%s]" % p
else:
	print "[-] Incorrect plaintext :("