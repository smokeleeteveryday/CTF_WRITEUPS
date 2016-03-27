#!/usr/bin/env python
#
# VolgaCTF 2016
# lazy (CRYPTO/250)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import os
import re
import string
import hashlib
import itertools
import base64
import shlex
from pwn import *
from struct import pack, unpack
from gmpy2 import mpz, invert

MAX_DATA_TO_RECEIVE_LENGTH = 8196

def data_to_int(s):
    return mpz(s.encode('hex'), 16)

def SHA1(data):
    return data_to_int(hashlib.sha1(data).hexdigest())

def sign(data, p, q, g, x, k):
    r = pow(g, k, p) % q
    s = (invert(k, q) * (SHA1(data) + x * r)) % q
    return (r, s)

def read_message(s):
    received_buffer = s.recv(4)
    if len(received_buffer) < 4:
        raise Exception('Error while receiving data')
    to_receive = struct.unpack('>I', received_buffer[0:4])[0]
    if to_receive > MAX_DATA_TO_RECEIVE_LENGTH:
        raise Exception('Too many bytes to receive')
    received_buffer = ''
    while (len(received_buffer) < to_receive):
        received_buffer += s.recv(to_receive - len(received_buffer))
    return received_buffer

def send_message(s, message):
    send_buffer = struct.pack('>I', len(message)) + message
    s.send(send_buffer)

def proof_of_work(proof, proof_len):
	# Should be sufficient charset
	charset = string.letters + string.digits

	# Bruteforce bounds
	lower_bound = 5
	upper_bound = 5

	# Find proof-of-work candidate
	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(lower_bound, upper_bound + 1)):
		candidate = proof + p
		assert (len(candidate) == proof_len)

		ha = hashlib.sha1()
		ha.update(candidate)
		if ((candidate[:-5] == proof) and (ha.digest()[-3:] == '\xff\xff\xff')):
			return candidate

	raise Exception("[-] Could not complete proof-of-work...")
	return

def do_auth(h):
	msg = read_message(h)
	pl, plen, p = re.findall('len\(x\)==([0-9]+?)\sand x\[:([0-9]+?)\]==(.*?)$', msg, re.M|re.I)[0]
	print "[*] Got [%s] (%s, %s), finding proof-of-work..." % (p, pl, plen)
	proof = proof_of_work(p, int(pl))
	print "[+] Found proof-of-work: [%s]" % proof
	send_message(h, proof)
	return

def do_cmd(h, r, s, cmd):
	r_str = str(r)
	s_str = str(s)
	cmd_exp = cmd
	send_message(h, r_str + "\n" + s_str + "\n" + cmd_exp)
	return

def import_public_key(keys_path):
    key_public = os.path.join(keys_path, 'key.public')
    assert (os.path.exists(key_public))
    with open(key_public, 'r') as f:
        data = f.read()
        d = data.split('\n')
        p = mpz(d[0])
        q = mpz(d[1])
        g = mpz(d[2])
        y = mpz(d[3])
        return (p, q, g, y)

def import_cmd_signature(cmd, keys_path):
    f = os.path.join(keys_path, '{0}.sig'.format(cmd))
    with open(f, 'r') as f:
        data = f.read()
        d = data.split('\n')
        (r, s) = (mpz(d[0]), mpz(d[1]))
        return (r, s)

def recover_k(r1, s1, r2, s2, d1, d2):
	assert (r1 == r2), "[-] r1 != r2"
	h1 = SHA1(d1)
	h2 = SHA1(d2)
	h = (h1 - h2)
	s = (s1 - s2)
	return ((h * invert(s, q)) % q)

def recover_x(r, s, k, d, q):
	return ((((s * k) - SHA1(d)) * invert(r, q)) % q)

def signed_shell(h, p, q, g, x, k):
	cmd = ''
	while ((cmd != 'exit') and (cmd != 'leave')):
		cmd = raw_input('$ ')
		r, s = sign(cmd, p, q, g, x, k)
		msg = str(r) + '\n' + str(s) + '\n' + cmd
		send_message(h, msg)
		msg = read_message(h)
		print msg
	return

host = 'lazy.2016.volgactf.ru'
port = 8889

p, q, g, y = import_public_key('./')
print "[*] Public key (p = %d, q = %d, g = %d, y = %d)" % (p, q, g, y)

r1, s1 = import_cmd_signature('exit', './')
r2, s2 = import_cmd_signature('leave', './')

print "[*] Signature(exit) (r = %d, s = %d)" % (r1, s1)
print "[*] Signature(leave) (r = %d, s = %d)" % (r2, s2)

k = recover_k(r1, s1, r2, s2, 'exit', 'leave')

print "[+] Recovered k = %d" % k

x = recover_x(r1, s1, k, 'exit', q)

print "[+] Recovered x = %d" % x

h = remote(host, port, timeout = None)

do_auth(h)

signed_shell(h, p, q, g, x, k)

h.close()