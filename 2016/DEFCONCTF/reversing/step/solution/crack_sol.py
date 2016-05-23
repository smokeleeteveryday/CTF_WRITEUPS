#
# DEF CON CTF Quals 2016
# step (re/2)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *

def inv_sbox(c):
	p = ''
	for i in xrange(len(c)):
		p += chr(((ord(c[i]) & 1) << 7) | ((ord(c[i]) & 0x20) << 1) | ((ord(c[i]) & 0x40) >> 1) | ((ord(c[i]) & 2) << 3) | ((ord(c[i]) & 0x80) >> 4) | ((ord(c[i]) & 8) >> 1) | ((ord(c[i]) & 4) >> 1) | ((ord(c[i]) & 0x10) >> 4))
	return p

key1 = "RotM"
key2 = inv_sbox("Please, may I have the flag now\x00")

host = 'step_8330232df7a7e389a20dd37eb55dfc13.quals.shallweplayaga.me'
port = 2345

h = remote(host, port, timeout = None)

print h.recvuntil('Key1: ')
h.sendline(key1)
print h.recvuntil('Key2: ')
h.sendline(key2)
h.interactive()

h.close()