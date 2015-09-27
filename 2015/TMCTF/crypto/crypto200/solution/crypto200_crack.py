#!/usr/bin/env python
#
# Trend Micro CTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import string
import itertools
from Crypto.Cipher import AES

def xor_blocks(b1, b2):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))

def encrypt(m, p, iv):
	aes = AES.new(p, AES.MODE_CBC, iv)
	return aes.encrypt(m)

def decrypt_block(c, k):
	aes = AES.new(k, AES.MODE_ECB)
	return aes.decrypt(c)

def brute_block(c_block, p_block, known_iv, known_key_prefix):
	assert(len(p_block) == 16)

	# Candidate list
	candidates = []

	# Known key prefix
	brute_count = (16 - len(known_key_prefix))

	# Character set
	charset = [chr(x) for x in xrange(0x00,0x100)]

	# Brute-force
	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(brute_count, brute_count + 1)):
		candidate = known_key_prefix + p
		d = decrypt_block(c_block, candidate)
		t = True
		# Check whether known plaintext/known iv constraint holds
		for offset in known_iv:
			t = (t and (p_block[offset] == chr(ord(d[offset]) ^ ord(known_iv[offset]))))

		if(t == True):
			candidates.append(candidate)

	return candidates

# Known key fragment
known_key_prefix = "5d6I9pfR7C1JQt"
# Known plaintext
plaintext = "The message is protected by AES!"
# Ciphertext block 1
c_block_1 = "307df037c689300bbf2812ff89bc0b49".decode('hex')
# Known fragments of ciphertext block 0, organized by offset
known_iv = {
			0: "\xFE",
			15: "\xC3"
}

# Obtain candidate keys
candidate_keys = brute_block(c_block_1, plaintext[16:], known_iv, known_key_prefix)

# Try all candidate keys
for k in candidate_keys:
	# Obtain ciphertext block 0 as IV of ciphertext block 1
	c_block_0 = xor_blocks(decrypt_block(c_block_1, k), plaintext[16:])

	# Obtain IV given known ciphertext block 0, plaintext block 0 and key
	IV = xor_blocks(decrypt_block(c_block_0, k), plaintext[:16])
	print "[+]Candidate IV: [%s]" % IV