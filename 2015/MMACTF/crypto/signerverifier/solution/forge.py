#!/usr/bin/python
#
# MMACTF 2015
# signerverifier (CRYPTO/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *

# Have our data of choice signed by the signer
def do_sign(sign_this, sign_port):
	h_sign = remote(host, sign_port, timeout = None)
	h_sign.sendline(str(sign_this))
	lines = h_sign.recv(1024).split("\n")
	h_sign.close()
	return long(lines[len(lines)-2])

host = 'cry1.chal.mmactf.link'
sign_port = 44815
verify_port = 44816

# Open connections
h_verify = remote(host, verify_port, timeout = None)
lines = h_verify.recv(1024).split("\n")

# Fetch public key
n = long(lines[0][4:])
e = long(lines[1][4:])

# Obtain our challenge plaintext
plaintext = long(lines[len(lines)-2])

# Find proper divisor, the lazy way
divisor = 2
for i in xrange(2, 100):
	if(plaintext % divisor == 0):
		break

assert(plaintext % divisor == 0)

# Divide, sign seperately
signed_0 = do_sign(plaintext / divisor, sign_port)
signed_1 = do_sign(divisor, sign_port)

# Apply modular reduction over product of signed parts to obtain signed product
signed = (signed_0 * signed_1) % n

# Send signature
h_verify.sendline(str(signed))

# Retrieve flag
print h_verify.recv(1024)

h_verify.close()