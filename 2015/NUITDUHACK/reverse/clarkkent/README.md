# Backdoor CTF 2015: Clark Kent

**Category:** Reversing
**Points:** 150
**Description:** 

> "There's a shadow inside all of us. But that doesn't mean you need to embrace it. You decide who you really are. And I know you'll make the right choice and become the hero you're destined to be." (Clark Kent)
> 
> Become that hero you're destined to be. [Discover and evolve](challenge/clark.tar.gz) your reversing powers.

## Write-up

The challenge consists of reversing a binary and finding the flag inside it. We start by checking our file:

>```bash
>$ file ./clark
> clark: ELF 32-bit LSB executable, Intel 80386, invalid version (SYSV), for GNU/Linux 2.6.24, dynamically linked (uses shared libs), corrupted section header size
>```

We can see we are dealing with a dynamically linked malformed 32-bit ELF executable. When we load the binary into IDA Pro we get similar warning about an invalid ELF header entry size, unsupported ELF version and invalid SHT table or offset. While it isn't strictly necessary to fix these as IDA Pro can deal with them perfectly well it takes little effort and will allow us to load the binary in gdb for later debugging. We fix the binary by using [HT Editor](http://hte.sourceforge.net) by setting the ELF header entry size to the appropriate 0x34, the ELF version to 0x00000001 and the SHT offset to 0x0 (which isn't correct but at least will allow gdb to load and run it properly).

The next thing we do is reloading the fixed binary into IDA Pro and decompiling the main routine (and the routines it calls) giving us the following pseudo-code (function and variable names added for clarity):

>```c
>signed int mainroutine()
>{
>  int v0; // ST14_4@4
>  signed int result; // eax@8
>  int v2; // [sp+Ch] [bp-14h]@1
>  int v3; // [sp+18h] [bp-8h]@4
>
>  if ( ptrace(0, 0, 1, 0) == -1 )
>  {
>    puts("Booh! Don't debug me!");
>    exit(1);
>  }
>  puts("Welcome to NDH2k15");
>  v0 = crypto1((int)&start_antidebug_loc, &end_antidebug_loc - &start_antidebug_loc);
>  v3 = (int)crypto2((const char *)&cipherarea, 390, v0, v2);
>  if ( crypto1(v3, 390) != 1468057730 )
>  {
>    puts("No no no! Don't patch me!");
>    exit(1);
>  }
>  if ( mprotect((void *)(v3 & 0xFFFFF000), 0x186u, 5) >= 0 )
>  {
>    ((void (*)(void))v3)();
>    result = 0;
>  }
>  else
>  {
>    result = 1;
>  }
>  return result;
>}
>
>int __cdecl crypto1(int addr, int len)
>{
>  int i; // [sp+8h] [bp-8h]@1
>  int v4; // [sp+Ch] [bp-4h]@1
>
>  v4 = 0;
>  for ( i = 0; i < len; ++i )
>    v4 = 16777619 * (*(_BYTE *)(i + addr) ^ v4);
>  return v4;
>}
>
>void *crypto2(const char *addr, ...)
>{
>  signed int i; // [sp+14h] [bp-24h]@5
>  unsigned int nmemb; // [sp+18h] [bp-20h]@1
>  void *v4; // [sp+1Ch] [bp-1Ch]@3
>
>  va_start(va, addr);
>  nmemb = *(unsigned int *)(int *)va;
>  if ( *(unsigned int *)(int *)va & 0xFFF )
>    nmemb = 4096
>          - (((((unsigned int)((unsigned __int64)(signed int)*(unsigned int *)(int *)va >> 32) >> 20)
>             + (_WORD)*(unsigned int *)(int *)va) & 0xFFF)
>           - ((unsigned int)((unsigned __int64)(signed int)*(unsigned int *)(int *)va >> 32) >> 20))
>          + *(unsigned int *)(int *)va;
>  v4 = calloc(nmemb, 1u);
>  if ( !v4 )
>    exit(1);
>  for ( i = 0; i < (signed int)*(unsigned int *)(int *)va; ++i )
>    *((_BYTE *)v4 + i) = addr[i] ^ (((_BYTE)*(unsigned int *)((int *)va + 1) << (char)i % 4) | (*(unsigned int *)((int *)va + 1) >> (-128 - (char)i % 4)));
>  return v4;
>}
>```

What happens is that the binary first checks if it is being debugged (using ptrace) and if so, it exits. It then calculates a checksum (using function crypto1) over the code area consisting of the debug check (to detect active breakpoints or patching) before decrypting a piece of code using the checksum. Finally it calculates a checksum over a large code area (including the main routine) to check for patches. If none are found mprotect is called to check for the correct protection permissions on the decrypted code area which is subsequently executed.

We first checked what the application did when run before delving further. If you run the application as a limited user it produces the following output:

>```bash
>$ ./clark
> Welcome to NDH2k15
> Need supercow power!!!
> Bye!
>```

When running as root, however, produces the following output:

>```bash
>$ ./clark
> Welcome to NDH2k15
? OMG! Why you root?
>```

And shuts down your system. So, needless to say, don't run untrusted binaries as root.

Manually debugging and patching (and removing patches and breakpoints before checks, etc.) would be a tedious process so instead let's use the LD_PRELOAD environment variable to specify an ELF shared library which will be loaded before all others. This will allow us to hook functionality in the binary and thus manipulate its behavior and the return values. In particular we want to disable the debugging check (by having a hooked ptrace return 0 when called with the above specified arguments) and dump the decrypted memory area right before it is executed (by having a hooked mprotect call dump the area it's called over to a file). To this end we wrote the [following](solution/clarksolution.c) little shared library:

>```c
>/*
>Nuit Du Hack CTF 2015
>CLARKKENT (REVERSING/150) Solution
>
>@a: Smoke Leet Everyday
>@u: https://github.com/smokeleeteveryday
>
>$ gcc -Wall -fPIC -shared -o clarksolution.so clarksolution.c -ldl
>$ LD_PRELOAD=./clarksolution.so ./clark
>
>*/
>#define _GNU_SOURCE
>
>#include <stdio.h>
>#include <sys/types.h>
>#include <dlfcn.h>
>
>typedef long (*orig_ptrace_f_type)(void* request, pid_t pid, void *addr, void *data);
>typedef int (*orig_mprotect_f_type)(void *addr, size_t len, int prot);
>
>int mprotect(void *addr, size_t len, int prot)
>{
>	orig_mprotect_f_type orig_mprotect;
>	orig_mprotect = (orig_mprotect_f_type)dlsym(RTLD_NEXT,"mprotect");
>
>	//dump memory area associated with specific mprotect call
>	if((((unsigned int)len) == 0x186) && (((unsigned int)prot) == 5))
>	{
>		//dump memory area to file
>		FILE* f = fopen("./dump", "wb");
>		fwrite(addr, 1, len, f);
>		fclose(f);
>		return orig_mprotect(addr, len, prot);
>	}
>	else
>	{
>		return orig_mprotect(addr, len, prot);
>	}
>}
>
>long ptrace(void* request, pid_t pid, void *addr, void *data)
>{
>	//trick specific ptrace call
>	if((((unsigned int)request) == 0) && (((unsigned int)pid) == 0) && (((unsigned int)addr) == 1) && (((unsigned int)0) == 0))
>	{
>		return 0;
>	}
>	else
>	{
>		orig_ptrace_f_type orig_ptrace;
>	    orig_ptrace = (orig_ptrace_f_type)dlsym(RTLD_NEXT,"ptrace");
>	    return orig_ptrace(request, pid, addr, data);
>	}
>}
>```

Compiling this and executing the target binary with preloading gives us the following result:

>```bash
>$ gcc -Wall -fPIC -shared -o clarksolution.so clarksolution.c -ldl
>$ LD_PRELOAD=./clarksolution.so ./clark
> Welcome to NDH2k15
> Need supercow power!!!
> Bye!
> $ ls
> 
> clark  clarksolution.c  clarksolution.so  dump
> $ strings dump
> RjZX
> Need supercow power!!!
> Bye!
> OMG! Why you root?
> Try again!
> Congratz!
> WhyN0P4tch?
> Alloc  : %x
> == Bef
>```

Where we can neatly spot the flag:

> WhyN0P4tch?