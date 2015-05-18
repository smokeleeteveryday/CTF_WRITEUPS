# DEF CON CTF Quals 2015: catwestern

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| DEF CON CTF Quals 2015 | catwestern | Coding |    1 |

**Description:**
>*meow catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999*

----------
## Write-up

If we connect to the server we get the following response:

>```bash
>$ nc catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999
>****Initial Register State****
>rax=0xfcf7659c7a4ad096
>rbx=0x1df0e8dfe8f70b53
>rcx=0x55004165472b9655
>rdx=0x1aa98e77006adf1
>rsi=0x949a482579724b11
>rdi=0x1e671d7b7ef9430
>r8=0x3251192496cee6a6
>r9=0x278d01e964b0efc8
>r10=0x1c5c8cca5112ad12
>r11=0x75a01cef4514d4f5
>r12=0xe109fd4392125cc7
>r13=0xe5e33405335ba0ff
>r14=0x633e16d0ec94137
>r15=0xb80a585e0cd42415
>****Send Solution In The Same Format****
>About to send 74 bytes: 
>hŒråRI‡ÔA]HÿÊIÇ¢éNhIÿÊHÿÃHÎIÇ^…6H¤Ã
>                                        MÃI÷ëH)ðHÆQØ8eHÿÀIÁÕH5Œm'Ã^C
>```

Seeing as we are faced with some x86_64 registers and 74 random bytes we probably have to emulate them (with the initial machine state set to the register values) and respond with the result.

We initially tried going for several emulators with python bindings but found them either too bloated for the job or incomplete (either due to lack of 64-bit support or incomplete instruction set support for certain instructions like 'bswap'). So [we decided to go with](solution/catwestern_solution.py) the less elegant but equally effective approach of creating a small executable that outputs its own state. In order to do this we simply wrote a nasm template that initialized all registers to the proper values, included the received shellcode (with the admittedly superfluous way of disassembling it first) and simply printf()'d the registers:

>```python
>#!/usr/bin/python
>#
># DEF CON CTF Quals 2015
># catwestern (CODING/1)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>from parse import *
>from capstone import *
>from os import system
>
># Disassemble a given blob
>def disassemble(blob):
>	dis = ""
>	md = Cs(CS_ARCH_X86, CS_MODE_64)
>	for i in md.disasm(blob, 0x0):
>		dis += "        %s\t%s\n" %(i.mnemonic, i.op_str)
>	return dis
>
># Evaluate shellcode
>def eval_sc(regs, blob):
>        disassembly = disassemble(blob)
>        print "[+]shellcode: [%s]" % disassembly
>	regs['shellcode'] = disassembly
>
>	nasm_code = """global main
>extern printf
>
>section .data
>        string: db "rax=0x%llx", 10, "rbx=0x%llx", 10, "rcx=0x%llx", 10, "rdx=0x%llx", 10, "rsi=0x%llx", 10, "rdi=0x%llx", 10, "r8=0x%llx", 10, "r9=0x%llx", 10, "r10=0x%llx", 10, "r11=0x%llx", 10, "r12=0x%llx", 10, "r13=0x%llx", 10, "r14=0x%llx", 10, "r15=0x%llx", 10, 0
> 
>section .text
>        main:
>
>        ; prologue
>        push rbp
>        mov rbp,rsp
>        sub rsp,0x60
>
>        mov dword [rbp-0x4], edi
>        mov qword [rbp-0x10], rsi
>
>        ; clear regs
>        xor rax, rax
>        xor rbx, rbx
>        xor rcx, rcx
>        xor rdx, rdx
>        xor rsi, rsi
>        xor rdi, rdi
>        xor r8, r8
>        xor r9, r9
>        xor r10, r10
>        xor r11, r11
>        xor r12, r12
>        xor r13, r13
>        xor r14, r14
>        xor r15, r15  
>
>        ; set regs
>
>        mov    rax, {rax}
>        mov    rbx, {rbx}
>        mov    rcx, {rcx}
>        mov    rdx, {rdx}
>        mov    rsi, {rsi}
>        mov    rdi, {rdi}
>        mov    r8, {r8}
>        mov    r9, {r9}
>        mov    r10, {r10}
>        mov    r11, {r11}
>        mov    r12, {r12}
>        mov    r13, {r13}
>        mov    r14, {r14}
>        mov    r15, {r15}
>
>        ; execute shellcode
>
>        call shellcode
>
>        ; display result
>
>        mov qword [rsp], rdi
>        mov qword [rsp+0x8], r8
>        mov qword [rsp+0x10], r9
>        mov qword [rsp+0x18], r10
>        mov qword [rsp+0x20], r11
>        mov qword [rsp+0x28], r12
>        mov qword [rsp+0x30], r13
>        mov qword [rsp+0x38], r14
>        mov qword [rsp+0x40], r15
>
>        mov r8, rdx
>        mov r9, rsi
>        mov rcx, rcx
>        mov rdx, rbx
>        mov rsi, rax
>
>        mov rax, 0
>        mov rdi, string
>        
>        call printf
>
>        ; exit
>        
>        leave
>        ret
>
>        shellcode:
>
>        {shellcode}""".format(**regs)
>
>	open("set.asm", "wb").write(nasm_code)
>	system("nasm -f elf64 -g set.asm; gcc set.o; ./a.out > set.out")
>	return open("set.out", "rb").read()
>
>host = "catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me"
>port = 9999
>
>h = remote(host, port)
>
>msg = h.recv(4096)
>
>regs = parse("****Initial Register State****\nrax={}\nrbx={}\nrcx={}\nrdx={}\nrsi={}\nrdi={}\nr8={}\nr9={}\nr10={}\nr11={}\nr12={}\nr13={}\nr14={}\nr15={}", msg)
>registers = {'rax': regs[0], 'rbx': regs[1], 'rcx': regs[2], 'rdx': regs[3], 'rsi': regs[4], 'rdi': regs[5], 'r8': regs[6], 'r9': regs[7], 'r10': regs[8], 'r11': regs[9], 'r12': regs[10], 'r13': regs[11], 'r14': regs[12], 'r15': regs[13]}
>
>print "[+]Got registers: [%s]" % registers
>
>msg = h.recv(4096)
>
>r = search ("****Send Solution In The Same Format****\nAbout to send {:d} bytes:{}", msg)
>
>size = int(r[0])
>offset = msg.find("bytes:")
>bytes = msg[offset+8:offset+8+size]
>
>print "[+]Got %d bytes" % size
>
>ret_state = eval_sc(registers, bytes)
>
>print "[+]Return state: [%s]" % ret_state
>
>h.send(ret_state+"\n")
>
>print h.recv(4096)
>
>h.close()
>```

which gives the following output when run:

>```bash
>$>catwestern_solution.py 
>[+] Opening connection to catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me on port 9999: Done
>[+]Got registers: [{'r14': '0xa7f4194a21a1ada', 'r15': '0x5f40fef8d75f6fb1', 'r12': '0xa84d301212e48f33', 'rsi': '0x47da6c3bdd3944df', 'r10': '0x98368cba467e7540', 'r11': '0x92042c356f0d861b', 'r9': '0xf6d68e704d0cbff4', 'rax': '0xbec2480fd894e83', 'r13': '0xb0d9cc6db84b2abf', 'rcx': '0x7680e68f14e3fc8e', 'rbx': '0x57d29de0982a6618', 'r8': '0x9d3ac7fb18a07ce4', 'rdx': '0xf97b180e33bac730', 'rdi': '0xee8a2c9af017972e'}]
>[+]Got 67 bytes
>[+]shellcode: [        neg    rcx
>        adc    r11, r13
>        sbb    rdx, 0x4eec042
>        push    rcx
>        pop    rdi
>        not    rbx
>        push    0x4304b422
>        shld    r11, r8, 0xf
>        add    r9, 0x7e21a84e
>        sub    r8, r14
>        shl    r12, 8
>        dec    rcx
>        add    rcx, r10
>        nop    
>        pop    rsi
>        shld    r15, r12, 8
>        or    rdx, 0x426c45c5
>        imul    r14, r15
>        ret    
>]
>[+]Return state: [rax=0xbec2480fd894e83
>rbx=0xa82d621f67d599e7
>rcx=0x21b5a62b319a78b1
>rdx=0xf97b180e6eec47ed
>rsi=0x4304b422
>rdi=0x897f1970eb1c0372
>r8=0x92bb86667686620a
>r9=0xf6d68e70cb2e6842
>r10=0x98368cba467e7540
>r11=0xfc5193ac586dce9d
>r12=0x4d301212e48f3300
>r13=0xb0d9cc6db84b2abf
>r14=0x4e74342758f0cd92
>r15=0x40fef8d75f6fb14d
>]
>The flag is: Cats with frickin lazer beamz on top of their heads!
>```