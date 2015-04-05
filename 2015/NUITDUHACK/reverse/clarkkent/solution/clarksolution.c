/*
Nuit Du Hack CTF 2015
CLARKKENT (REVERSING/150) Solution

@a: Smoke Leet Everyday
@u: https://github.com/smokeleeteveryday

$ gcc -Wall -fPIC -shared -o clarksolution.so clarksolution.c -ldl
$ LD_PRELOAD=./clarksolution.so ./clark

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>

typedef long (*orig_ptrace_f_type)(void* request, pid_t pid, void *addr, void *data);
typedef int (*orig_mprotect_f_type)(void *addr, size_t len, int prot);

int mprotect(void *addr, size_t len, int prot)
{
	orig_mprotect_f_type orig_mprotect;
	orig_mprotect = (orig_mprotect_f_type)dlsym(RTLD_NEXT,"mprotect");

	//dump memory area associated with specific mprotect call
	if((((unsigned int)len) == 0x186) && (((unsigned int)prot) == 5))
	{
		//dump memory area to file
		FILE* f = fopen("./dump", "wb");
		fwrite(addr, 1, len, f);
		fclose(f);
		return orig_mprotect(addr, len, prot);
	}
	else
	{
		return orig_mprotect(addr, len, prot);
	}
}

long ptrace(void* request, pid_t pid, void *addr, void *data)
{
	//trick specific ptrace call
	if((((unsigned int)request) == 0) && (((unsigned int)pid) == 0) && (((unsigned int)addr) == 1) && (((unsigned int)0) == 0))
	{
		return 0;
	}
	else
	{
		orig_ptrace_f_type orig_ptrace;
	    orig_ptrace = (orig_ptrace_f_type)dlsym(RTLD_NEXT,"ptrace");
	    return orig_ptrace(request, pid, addr, data);
	}
}