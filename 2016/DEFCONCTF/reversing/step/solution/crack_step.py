#
# DEF CON CTF Quals 2016
# step (re/2)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import idaapi

def derive_key(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def repeating_key_xor(start_address, buffer_len, key):
	for i in xrange(buffer_len):
		c = idaapi.get_byte(start_address + i) ^ ord(key[(i % len(key))])
		idaapi.patch_byte(start_address + i, c)	
	return

def selfmod_decoder(rip_address):
	if ((rip_address > 0x400935) and (rip_address <= 0x40103D)):
		idaapi.patch_byte(rip_address, idaapi.get_byte(rip_address) ^ (rip_address & 0xFF))
	return

routine_1_address = 0x400E0E
candidate_plaintext = [0x55, 0x48, 0x89, 0xE5]
key1 = ''.join([chr(idaapi.get_byte(routine_1_address + i) ^ candidate_plaintext[i]) for i in xrange(len(candidate_plaintext))])

print "[+] Key1: [%s]" % key1

# Step 1
repeating_key_xor(routine_1_address, 0x9E, key1)

# Step 2
routine_2_address = 0x400936
repeating_key_xor(routine_2_address, 0xEC, key1)

# Step 3 to be applied manually (or as a per-instruction SIGTRAP hook)