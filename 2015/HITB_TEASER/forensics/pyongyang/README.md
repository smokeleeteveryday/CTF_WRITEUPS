# Hack In The Box Amsterdam CTF Teaser 2015: Pyongyang

**Category:** Forensics
**Points:** 1000
**Description:** 

>While doing forensics on the HEAVENWEB's server we found a possible ACTOR.
>We scanned the interweb for possible traces left by this ACTOR and found an opendir containing [HEAVENWEB_SCRAPE.tar.xz](http://www.speedyshare.com/Yv8uj/HEAVENWEB-SCRAPE.tar.xz) [sha256: 6188c47846d306f29315c5df85c507052d20e98e592e08bdf1b35b46c7f84564].
>
>We believe they use a proprietary crypto application only known to this ACTOR.
>
>Are you able to find the flag?
>
>HINT: [https://www.youtube.com/watch?v=zuxlLLeKZZ8](https://www.youtube.com/watch?v=zuxlLLeKZZ8)

## Write-up

The HEAVENWEB_SCRAPE.tar.xz archive consists of the following files:

- **HITB2015_FOR1000.dmp**
- **HITB_FOR1000_2015**

As a starting point we ran *file* on the files to be able to determine their contents, using their headers.

>[user@box]$ file *
>HITB2015_FOR1000.dmp: ELF 64-bit LSB core file x86-64, version 1 (SYSV)
>HITB_FOR1000_2015:    data

Since *HITB2015_FOR1000.dmp* was supposed to be an ELF binary, we tried to run *readelf* on the file, to
be able to get more info on the file.

>[user@box]$ readelf -a HITB2015_FOR1000.dmp
>ELF Header:
>  Magic:   7f 45 4c 46 02 01 00 00 00 00 00 00 00 00 00 00 
>  Class:                             ELF64
>  Data:                              2's complement, little endian
>  Version:                           0 
>  OS/ABI:                            UNIX - System V
>  ABI Version:                       0
>  Type:                              CORE (Core file)
>  Machine:                           Advanced Micro Devices X86-64
>  Version:                           0x1
>  Entry point address:               0x0
>  Start of program headers:          64 (bytes into file)
>  Start of section headers:          0 (bytes into file)
>  Flags:                             0x0
>  Size of this header:               64 (bytes)
>  Size of program headers:           56 (bytes)
>  Number of program headers:         10
>  Size of section headers:           64 (bytes)
>  Number of section headers:         0
>  Section header string table index: 0
>
>There are no sections in this file.
>
>There are no sections to group in this file.
>
>Program Headers:
>  Type           Offset             VirtAddr           PhysAddr
>                 FileSiz            MemSiz              Flags  Align
>  NOTE           0x0000000000000270 0x0000000000000000 0x0000000000000000
>                 0x0000000000000480 0x0000000000000480  R      0
>  LOAD           0x00000000000006f0 0x0000000000000000 0x0000000000000000
>                 0x0000000020000000 0x0000000020000000  R      0
>  LOAD           0x00000000200006f0 0x0000000000000000 0x00000000e0000000
>                 0x0000000000c00000 0x0000000000c00000  R      0
>  LOAD           0x0000000020c006f0 0x0000000000000000 0x00000000f0000000
>                 0x0000000000000000 0x0000000000020000  R      0
>  LOAD           0x0000000020c006f0 0x0000000000000000 0x00000000f0400000
>                 0x0000000000400000 0x0000000000400000  R      0
>  LOAD           0x00000000210006f0 0x0000000000000000 0x00000000f0800000
>                 0x0000000000004000 0x0000000000004000  R      0
>  LOAD           0x00000000210046f0 0x0000000000000000 0x00000000f0804000
>                 0x0000000000000000 0x0000000000001000  R      0
>  LOAD           0x00000000210046f0 0x0000000000000000 0x00000000f0806000
>                 0x0000000000000000 0x0000000000002000  R      0
>  LOAD           0x00000000210046f0 0x0000000000000000 0x00000000fee00000
>                 0x0000000000000000 0x0000000000001000  R      0
>  LOAD           0x00000000210046f0 0x0000000000000000 0x00000000ffff0000
>                 0x0000000000010000 0x0000000000010000  R      0
>
>There is no dynamic section in this file.
>
>There are no relocations in this file.
>
>The decoding of unwind sections for machine type Advanced Micro Devices X86-64 is not currently supported.
>
>Dynamic symbol information is not available for displaying symbols.
>
>No version information found in this file.
>
>Displaying notes found at file offset 0x00000270 with length 0x00000480:
>  Owner                 Data size       Description
>  VBCORE               0x00000018       Unknown note type: (0x00000b00)
>  VBCPU                0x00000440       Unknown note type: (0x00000b01)

The output above states that *HITB2015_FOR1000.dmp* does not contain any sections at all, this imputes that it 
is not a valid ELF binary. 

Since it wasn't a valid ELF binary we decided to give strings a shot. This revealed some interesting strings:

- /boot/vmlinuz-2.6.38.8-24.rs3.0.i686  ro root=UUID=ed27ac6e-775f-4c6e-93c3-cea1fb339337 quiet vga=0x317
- /boot/grub/stage2 /boot/grub/grub.conf
- internal error: the second sector of Stage 2 is unknown.

Initially we thought *HITB2015_FOR1000.dmp* was a bootable disk image, since the strings stated above were
one of the first strings that had been encountered, but a bootable disk image wouldn't start with an ELF header.

As *HITB2015_FOR1000.dmp* started with an ELF header, and it contained strings related to grub, we concluded
that it actually was a memory dump.

Now we knew what *HITB2015_FOR1000.dmp* was, we took a look at *HITB_FOR1000_2015*. Running strings on it revealed
the following interesting strings:

>[user@box]$ strings HITB_FOR1000_2015
>BOKEM
>ext3
>pilsung
>essiv
>sha256
>5135c956f0d1dbacaaaabebc7b3a659f93a0c2f4
>21bfcf58-79a4-4c87-5b48-c88689cfc749

*BOKEM* was mentioned in the referenced youtube video, it's an application that enabled users to 
create encrypted images. With the fact that Red Star 3.0 is a OS based on Linux, we expected that 
Bokem was a wrapper that made use of Linux's dm-crypt subsystem.

This lead us to the conclusion that *HITB2015_FOR1000.dmp* contained a key that enabled us to
decrypt the *HITB_FOR1000_2015* file.

We found a paper that described how to extract dm-crypt keys from memory dumps. It can be found at:
- http://events.ccc.de/camp/2007/Fahrplan/attachments/1300-Cryptokey_forensics_A.pdf

The paper contained some C code thatshould be able to extract the key from *HITB2015_FOR1000.dmp*. 
We compiled the code, and ran it on the memory dump. Unfortunately this didn't work out.
As the paper was released in 2007, and Red Star uses ernel that has been released in 2012,
we suspected that the key storage struct used by dm-crupt, had changed.

We looked around for other versions of *keysearch.c*, which brought us to the following repository:
- https://github.com/scintill/keysearch

Unfortunately that version wasn't compatible with Red Star's kernel either (2.6.38.8), so we decided
to [patch scintill's](solution/pyongyang_keysearch.c) code.

>[user@box]$ ./keysearch HITB2015_FOR1000.dmp 
>offset: 3731552384 blocks
>iv_size : 16
>keylength: 256
>keyparts: 1
>flags : 2
>key: BE6B50300E87EA15DA0884D5E44781FFBF8000286DB03DADE00CE4B64CAD0BF4 

Now we had to determine how we could decrypt *HITB_FOR1000_2015* with the key/hash we had
just found. 

We created a dummy image, and mounted it using Bokem. In the meaintime we captured all execve syscalls, and
saw how Bokem mounts images:

>losetup /dev/loop0 /root/dummy_image
>dmsetup create DUMMY_FS --table "0 102399 crypt pilsung-cbc-essiv:sha256 c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 0 /dev/loop0 1"

So the only thing left was to decrypt the encrypted image.

>[user@box]# losetup /dev/loop0 HITB_FOR1000_2015
>[user@box]# dmsetup create FLAG --table "0 102399 crypt pilsung-cbc-essiv:sha256 be6b50300e87ea15da0884d5e44781ffbf8000286db03dade00ce4b64cad0bf4 0 /dev/loop0 1"
>[user@box]# mount /dev/mapper/FLAG /mnt
>[user@box]# cat /mnt/hitb_flag.txt
>HITB{4468eaa8a5d6fdbff208dac223afb81c}