#!/usr/bin/env python
#
# Plaid CTF 2016
# rabit (CRYPTO/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import re
import math
import string
import hashlib
import itertools
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

def encrypt(m, N):
    return pow(m, 2, N)

def proof_of_work(prefix, plen, endv):
	# Should be sufficient charset
	charset = string.letters + string.digits

	# Bruteforce bounds
	lower_bound = plen - len(prefix)
	upper_bound = plen - len(prefix)

	# Find proof-of-work candidate
	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(lower_bound, upper_bound + 1)):
		candidate = prefix + p
		assert (len(candidate) == plen)

		if ((candidate[:len(prefix)] == prefix) and (hashlib.sha1(candidate).hexdigest()[-6:] == endv)):
			return candidate

	raise Exception("[-] Could not complete proof-of-work...")
	return

def give_proof_of_work(h, line):
	prefix, plen, endv = re.findall('starting\swith\s(.+?),\sof\slength\s([0-9]+?),\ssuch\sthat\sits\ssha1\ssum\sends\sin\s(.+?)$', line, re.M|re.I)[0]
	print "[*] Got proof-of-work request [%s] (%s, %s), finding proof-of-work..." % (prefix, plen, endv)
	proof = proof_of_work(prefix, int(plen), endv)
	print "[+] Found proof-of-work: [%s]" % proof
	h.sendline(proof)
	return

def extract_n(line):
	return re.findall('N = (.*?)$', line, re.M|re.I)[0]

def extract_eflag(line):
	return re.findall(':\s(.*?)$', line, re.M|re.I)[0]

def extract_lsb(line):
	return re.findall('lsb\sis\s(.*?)$', line, re.M|re.I)[0]

def decryption_oracle(ciphertext):
	h.recvuntil('Give a ciphertext: ')
	h.sendline(ciphertext)
	lsb_line = h.recvline()
	if not(lsb_line.startswith('lsb is')):
		raise Exception("[-] Invalid lsb line [%s]" % lsb_line)
	return extract_lsb(lsb_line)

def lsb_oracle_attack(encrypted_flag, N):
	m_lowerbound = 0
	m_upperbound = N
	iter_count = math.log(N, 2) # iterate log2(N) times
	C = encrypted_flag

	for i in xrange(0, long(math.ceil(long(iter_count)))):
		# c = (2^2 mod N * m^2 mod N) = ((2^2 * m^2) mod N) = (2m)^2 mod N
		C = ((encrypt(2, N) * C) % N)
		p_lsb = decryption_oracle(str(C))

		if (int(p_lsb) == 1):
			# mul_fac*m is odd so mul_fac*m > N (remainder after modular reduction is odd since N is odd)
			# Hence m > N/mul_fac so we increase the lowerbound
			m_lowerbound = ((m_upperbound + m_lowerbound) / 2)
		elif (int(p_lsb) == 0):
			# mul_fac*m is even so mul_fac*m <= N
			# Hence m <= N/mul_fac so we decrease the upperbound
			m_upperbound = ((m_upperbound + m_lowerbound) / 2)

		print "[*] %s" % long_to_bytes(m_upperbound)

	return

host = 'rabit.pwning.xxx'
port = 7763

welcome_msg = 'Welcome to the LSB oracle!'
eflag_msg = 'Encrypted Flag'

h = remote(host, port, timeout = None)

l1 = h.recvline()
l2 = h.recvline()

give_proof_of_work(h, l2)

welcome = h.recvline()

if not(welcome.startswith(welcome_msg)):
	raise Exception("[-] Invalid welcome message [%s]..." % welcome)

N = long(extract_n(welcome))

encrypted_flag_msg = h.recvline()

if not(encrypted_flag_msg.startswith(eflag_msg)):
	raise Exception("[-] Invalid eflag msg [%s]" % encrypted_flag_msg)

encrypted_flag = long(extract_eflag(encrypted_flag_msg))

print "[*] N: [%s]" % N
print "[*] C: [%s]" % encrypted_flag

print "[*] Starting LSB oracle attack ..."

flag = lsb_oracle_attack(encrypted_flag, N)

h.close()