# CSAWCTF 2015: FTP

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| CSAWCTF 2015 | FTP | Reversing |    300 |

**Description:**
>*We found an ftp service, I'm sure there's some way to log on to it.*
>
>*nc 54.175.183.202 12012*
>
>*[ftp_0319deb1c1c033af28613c57da686aa7](challenge/ftp)*

----------
## Write-up

We are given the 64-bit ELF binary of a custom FTP daemon and are given the task to log in to it. We start by loading it up in IDA, annotating the pseudo-code (setting proper function names, renaming variables, etc.) to get this function which is called every time an [*accept*](http://linux.die.net/man/2/accept) call is successful:

```c
void __fastcall __noreturn core(int socket)
{
  unsigned int v1; // eax@1
  char *v2; // rax@5
  int i; // [sp+18h] [bp-978h]@4
  int v4; // [sp+1Ch] [bp-974h]@4
  char *v5; // [sp+20h] [bp-970h]@4
  void *ptr; // [sp+28h] [bp-968h]@4
  int buffer; // [sp+30h] [bp-960h]@1
  char *v8; // [sp+40h] [bp-950h]@23
  char *v9; // [sp+48h] [bp-948h]@13
  const char *v10; // [sp+50h] [bp-940h]@12
  __int64 v11; // [sp+F0h] [bp-8A0h]@2
  int v12; // [sp+4F0h] [bp-4A0h]@11
  char s2[128]; // [sp+500h] [bp-490h]@4
  char buf; // [sp+580h] [bp-410h]@1
  __int64 v15; // [sp+988h] [bp-8h]@1

  v15 = *MK_FP(__FS__, 40LL);
  alarm(0x41u);
  v1 = time(0LL);
  srand(v1);
  memset(&buffer, 0, 0x4C8uLL);
  buffer = socket;
  if ( getcwd(&buf, 0x400uLL) )
  {
    strcpy((char *)&v11, &buf);
    send_msg(socket, off_6041A8);
    while ( 1 )
    {
      memset(s2, 0, 0x80uLL);
      v5 = (char *)recv_msg(socket);
      ptr = v5;
      v4 = strlen(v5);
      for ( i = 0; *v5 != 32 && v4 - 1 >= i; ++i )
      {
        v2 = v5++;
        s2[i] = *v2;
      }
      if ( *v5 == 32 )
        ++v5;
      v5[strlen(v5) - 1] = 0;
      if ( !strncasecmp("USER", s2, 4uLL) )
      {
        if ( v12 == 1 )
        {
          send_msg(socket, "Cannot change user  ");
          send_msg(socket, v10);
          send_msg(socket, "\n");
        }
        else
        {
          v10 = v5;
          v9 = v5;
          login_procedure((__int64)&buffer);
        }
      }
      else if ( !strncasecmp("PASS", s2, 4uLL) )
      {
        send_msg(socket, "send user first\n");
      }
      else if ( !strncasecmp("HELP", s2, 4uLL) )
      {
        send_msg(socket, help_list);
      }
      else if ( v12 )
      {
        if ( !strncasecmp("REIN", s2, 4uLL) )
        {
          v12 = 0;
        }
        else if ( !strncasecmp("PORT", s2, 4uLL) )
        {
          v8 = s2;
          v9 = v5;
          PORT((__int64)&buffer);
        }
        else if ( !strncasecmp("PASV", s2, 4uLL) )
        {
          v8 = s2;
          v9 = v5;
          PASV((__int64)&buffer, (__int64)s2);
        }
        else if ( !strncasecmp("STOR", s2, 4uLL) )
        {
          v8 = s2;
          v9 = v5;
          STOR((__int64)&buffer);
        }
        else if ( !strncasecmp("RETR", s2, 4uLL) )
        {
          v8 = s2;
          v9 = v5;
          RETR((__int64)&buffer);
        }
        else
        {
          if ( !strncasecmp("QUIT", s2, 4uLL) )
          {
            v8 = s2;
            v9 = v5;
            QUIT(&buffer);
          }
          if ( !strncasecmp("LIST", s2, 4uLL) )
          {
            v8 = s2;
            v9 = v5;
            LIST((__int64)&buffer, (__int64)s2);
          }
          else if ( !strncasecmp("SYST", s2, 4uLL) )
          {
            v8 = s2;
            v9 = v5;
            SYST(&buffer);
          }
          else if ( !strncasecmp("SIZE", s2, 4uLL) )
          {
            v8 = s2;
            v9 = v5;
            SIZE((__int64)&buffer);
          }
          else if ( !strncasecmp("NOOP", s2, 4uLL) )
          {
            v8 = s2;
            v9 = v5;
            NOOP(&buffer);
          }
          else if ( !strncasecmp("PWD", s2, 3uLL) )
          {
            v8 = s2;
            v9 = v5;
            PWD((__int64)&buffer);
          }
          else if ( !strncasecmp("CWD", s2, 3uLL) )
          {
            v8 = s2;
            v9 = v5;
            CWD((__int64)&buffer);
          }
          else if ( !strncasecmp("RDF", s2, 3uLL) )
          {
            v8 = s2;
            v9 = v5;
            RDF(&buffer);
          }
          else
          {
            send_msg(socket, "Command Not Found :(\n");
          }
        }
      }
      else
      {
        send_msg(socket, "login with USER first\n");
      }
      free(ptr);
    }
  }
  error(4207778LL);
}
```

This code is clearly a command handler for raw FTP commands. The command of interest for us is the "USER" command and the corresponding *login_procedure*:

```c
__int64 __fastcall login_procedure(__int64 some_struct)
{
  char *v1; // rax@2
  int i; // [sp+18h] [bp-A8h]@1
  int v4; // [sp+1Ch] [bp-A4h]@1
  char *v5; // [sp+20h] [bp-A0h]@1
  void *ptr; // [sp+28h] [bp-98h]@1
  char s[136]; // [sp+30h] [bp-90h]@1
  __int64 v8; // [sp+B8h] [bp-8h]@1

  v8 = *MK_FP(__FS__, 40LL);
  memset(s, 0, 0x80uLL);
  send_msg(*(_DWORD *)some_struct, "Please send password for user ");
  send_msg(*(_DWORD *)some_struct, *(const char **)(some_struct + 32));
  send_msg(*(_DWORD *)some_struct, "\n");
  v5 = (char *)recv_msg(*(_DWORD *)some_struct);
  ptr = v5;
  v4 = strlen(v5);
  for ( i = 0; *v5 != 32 && v4 - 1 >= i; ++i )
  {
    v1 = v5++;
    s[i] = *v1;
  }
  if ( *v5 == 0x20 )
    ++v5;
  if ( !strncasecmp("PASS", s, 4uLL) )
  {
    *(_QWORD *)(some_struct + 40) = v5;
    magic(*(_QWORD *)(some_struct + 40));
    if ( !strncmp(*(const char **)(some_struct + 0x20), "blankwall", 9uLL)
      && (unsigned int)magic(*(_QWORD *)(some_struct + 0x28)) == 0xD386D209 )
    {
      *(_DWORD *)(some_struct + 1216) = 1;
      send_msg(*(_DWORD *)some_struct, "logged in\n");
      some_global = 0x66;
    }
    else
    {
      send_msg(*(_DWORD *)some_struct, "Invalid login credentials\n");
      free(ptr);
    }
  }
  else
  {
    send_msg(*(_DWORD *)some_struct, "login with USER PASS\n");
  }
  return *MK_FP(__FS__, 40LL) ^ v8;
}
```

As we can see the login procedure compares the supplied user name with the hardcoded string *blankwall* which is our target username. The supplied password is pulled through the *magic* routine and its result compared to 0xD386D209. This intuitively feels like a hash function and looking at the pseudo-code for *magic* confirms this:

```c
__int64 __fastcall magic(__int64 a1)
{
  int i; // [sp+10h] [bp-8h]@1
  int v3; // [sp+14h] [bp-4h]@1

  v3 = 0x1505;
  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    v3 = 0x21 * v3 + *(_BYTE *)(i + a1);
  return (unsigned int)v3;
}
```

Which translates to the following python code:

```python
def hashf(inp):
    # Multiplier
    M = 0x21
    # Modulus
    P = 2**32
    # Initial state
    state = 0x1505
    for c in inp:
        state = ((state * M) + ord(c)) % P
    return state
```

We are dealing with a [multiplicative hash function](http://www.strchr.com/hash_functions) with initialization value 0x1505, multiplier 0x21 and (implicit) modulus 4294967296 (due to 32-bit integer wraparound). It's unlikely we can losslessly revert the hash (due to modular reduction and non-prime multiplier) so instead we go for the [incremental divide-and-conquer approach](https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/MMACTF/reversing/simple_hash) we used in the *simple_hash* challenge in MMACTF 2015.

We also see the following, custom, raw FTP command handler:

```c
ssize_t __fastcall RDF(int *a1)
{
  ssize_t result; // rax@2
  void *ptr; // [sp+10h] [bp-10h]@1
  FILE *stream; // [sp+18h] [bp-8h]@1

  ptr = malloc(0x28uLL);
  stream = fopen("re_solution.txt", "r");
  if ( stream )
  {
    fread(ptr, 0x28uLL, 1uLL, stream);
    result = send_msg(*a1, (const char *)ptr);
  }
  else
  {
    result = send_msg(*a1, "Error reading RE flag please contact an organizer");
  }
  return result;
}
```

Which gives us the flag. So our goal is to crack the hash, log in as blankwall and execute the RDF command.

Using [this script](solution/ftp_crack.py) we get:

```bash
[*]Cracking h = 0xd386d209
[*]Trying length 1...
[*]Trying length 2...
[*]Trying length 3...
[*]Trying length 4...
[*]Trying length 5...
[*]Trying length 6...
[+]Cracked input: [UJD737] (0xd386d209)
[+] Opening connection to 54.175.183.202 on port 12012: Done
Welcome to FTP server

Please send password for user 
blankwall

logged in

UNIX Type: L8

/home/ctf


flag{n0_c0ok1e_ju$t_a_f1ag_f0r_you}
```