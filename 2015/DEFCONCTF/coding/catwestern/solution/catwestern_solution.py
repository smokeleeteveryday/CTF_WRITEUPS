#!/usr/bin/python
#
# DEF CON CTF Quals 2015
# catwestern (CODING/1)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from parse import *
from capstone import *
from os import system

# Disassemble a given blob
def disassemble(blob):
	dis = ""
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for i in md.disasm(blob, 0x0):
		dis += "        %s\t%s\n" %(i.mnemonic, i.op_str)
	return dis

# Evaluate shellcode
def eval_sc(regs, blob):
        disassembly = disassemble(blob)
        print "[+]shellcode: [%s]" % disassembly
	regs['shellcode'] = disassembly

	nasm_code = """global main
extern printf

section .data
        string: db "rax=0x%llx", 10, "rbx=0x%llx", 10, "rcx=0x%llx", 10, "rdx=0x%llx", 10, "rsi=0x%llx", 10, "rdi=0x%llx", 10, "r8=0x%llx", 10, "r9=0x%llx", 10, "r10=0x%llx", 10, "r11=0x%llx", 10, "r12=0x%llx", 10, "r13=0x%llx", 10, "r14=0x%llx", 10, "r15=0x%llx", 10, 0
 
section .text
        main:

        ; prologue
        push rbp
        mov rbp,rsp
        sub rsp,0x60

        mov dword [rbp-0x4], edi
        mov qword [rbp-0x10], rsi

        ; clear regs
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx
        xor rdx, rdx
        xor rsi, rsi
        xor rdi, rdi
        xor r8, r8
        xor r9, r9
        xor r10, r10
        xor r11, r11
        xor r12, r12
        xor r13, r13
        xor r14, r14
        xor r15, r15  

        ; set regs

        mov    rax, {rax}
        mov    rbx, {rbx}
        mov    rcx, {rcx}
        mov    rdx, {rdx}
        mov    rsi, {rsi}
        mov    rdi, {rdi}
        mov    r8, {r8}
        mov    r9, {r9}
        mov    r10, {r10}
        mov    r11, {r11}
        mov    r12, {r12}
        mov    r13, {r13}
        mov    r14, {r14}
        mov    r15, {r15}

        ; execute shellcode

        call shellcode

        ; display result

        mov qword [rsp], rdi
        mov qword [rsp+0x8], r8
        mov qword [rsp+0x10], r9
        mov qword [rsp+0x18], r10
        mov qword [rsp+0x20], r11
        mov qword [rsp+0x28], r12
        mov qword [rsp+0x30], r13
        mov qword [rsp+0x38], r14
        mov qword [rsp+0x40], r15

        mov r8, rdx
        mov r9, rsi
        mov rcx, rcx
        mov rdx, rbx
        mov rsi, rax

        mov rax, 0
        mov rdi, string
        
        call printf

        ; exit
        
        leave
        ret

        shellcode:

        {shellcode}""".format(**regs)

	open("set.asm", "wb").write(nasm_code)
	system("nasm -f elf64 -g set.asm; gcc set.o; ./a.out > set.out")
	return open("set.out", "rb").read()

host = "catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me"
port = 9999

h = remote(host, port)

msg = h.recv(4096)

regs = parse("****Initial Register State****\nrax={}\nrbx={}\nrcx={}\nrdx={}\nrsi={}\nrdi={}\nr8={}\nr9={}\nr10={}\nr11={}\nr12={}\nr13={}\nr14={}\nr15={}", msg)
registers = {'rax': regs[0], 'rbx': regs[1], 'rcx': regs[2], 'rdx': regs[3], 'rsi': regs[4], 'rdi': regs[5], 'r8': regs[6], 'r9': regs[7], 'r10': regs[8], 'r11': regs[9], 'r12': regs[10], 'r13': regs[11], 'r14': regs[12], 'r15': regs[13]}

print "[+]Got registers: [%s]" % registers

msg = h.recv(4096)

r = search ("****Send Solution In The Same Format****\nAbout to send {:d} bytes:{}", msg)

size = int(r[0])
offset = msg.find("bytes:")
bytes = msg[offset+8:offset+8+size]

print "[+]Got %d bytes" % size

ret_state = eval_sc(registers, bytes)

print "[+]Return state: [%s]" % ret_state

h.send(ret_state+"\n")

print h.recv(4096)

h.close()