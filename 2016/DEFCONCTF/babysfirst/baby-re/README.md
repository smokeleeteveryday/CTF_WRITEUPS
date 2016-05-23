# DEF CON CTF Quals 2016: baby-re

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| DEF CON CTF Quals | baby-re | Baby's First | 1 |

### Description
> Get to reversing.

## Write-up

This is a straightforward 'keygenme'. We're given a [binary](challenge) which we decompile using IDA:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int result; // eax@4
  __int64 v4; // rbx@4
  unsigned int v5; // [sp+0h] [bp-60h]@1
  unsigned int v6; // [sp+4h] [bp-5Ch]@1
  unsigned int v7; // [sp+8h] [bp-58h]@1
  unsigned int v8; // [sp+Ch] [bp-54h]@1
  unsigned int v9; // [sp+10h] [bp-50h]@1
  unsigned int v10; // [sp+14h] [bp-4Ch]@1
  unsigned int v11; // [sp+18h] [bp-48h]@1
  unsigned int v12; // [sp+1Ch] [bp-44h]@1
  unsigned int v13; // [sp+20h] [bp-40h]@1
  unsigned int v14; // [sp+24h] [bp-3Ch]@1
  unsigned int v15; // [sp+28h] [bp-38h]@1
  unsigned int v16; // [sp+2Ch] [bp-34h]@1
  unsigned int v17; // [sp+30h] [bp-30h]@1
  __int64 v18; // [sp+38h] [bp-28h]@1

  v18 = *MK_FP(__FS__, 40LL);
  printf("Var[0]: ", argv, envp);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v5);
  printf("Var[1]: ", &v5);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v6);
  printf("Var[2]: ", &v6);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v7);
  printf("Var[3]: ", &v7);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v8);
  printf("Var[4]: ", &v8);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v9);
  printf("Var[5]: ", &v9);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v10);
  printf("Var[6]: ", &v10);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v11);
  printf("Var[7]: ", &v11);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v12);
  printf("Var[8]: ", &v12);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v13);
  printf("Var[9]: ", &v13);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v14);
  printf("Var[10]: ", &v14);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v15);
  printf("Var[11]: ", &v15);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v16);
  printf("Var[12]: ", &v16);
  fflush(_bss_start);
  __isoc99_scanf("%d", &v17);
  if ( (unsigned __int8)CheckSolution((__int64)&v5) )
    printf("The flag is: %c%c%c%c%c%c%c%c%c%c%c%c%c\n", v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17);
  else
    puts("Wrong");
  result = 0;
  v4 = *MK_FP(__FS__, 40LL) ^ v18;
  return result;
}
```

We're asked for an array of 13 integers which are passed to `CheckSolution`. If `CheckSolution` validates our input that same input is output (as characters) as the flag. This hints at the input characters probably being within ASCII-printable range, good to know. We cant't properly decompile `CheckSolution` because apparently the 'function frame is wrong' according to IDA. According to [hex rays](https://www.hex-rays.com/products/decompiler/manual/failures.shtml#12) "the most probable cause is that the return address area is missing in the frame or the function farness (far/near) does not match it". We solved this by undefining the routine's code (right click -> Undefine), recasting it to code (pressing 'C' with cursor on data) and recreating a function (rightclick at entrypoint -> Create function). If we then try to decompile it complains about a 'positive SP value' at address `0x4010FA` instead which indicates that "the stack pointer at the specified address is higher than the initial stack pointer". We check out the function disassembly and see a lot of bogus 'dead code' interwoven with jumps over it including this one before `0x4010FA`:

```asm
.text:00000000004010F6 2C0                 jmp     short loc_4010FA
.text:00000000004010F6     ; ---------------------------------------------------------------------------
.text:00000000004010F8 2C8                 leave
.text:00000000004010F9 000                 pop     rax
.text:00000000004010FA     ; ---------------------------------------------------------------------------
.text:00000000004010FA
.text:00000000004010FA     loc_4010FA:                             ; CODE XREF: CheckSolution+A30j
.text:00000000004010FA 2C8                 mov     [rbp+var_EC], 140C8h
```

Seeing as how they're skipped over anyway we turn the `leave; pop rax` instructions into data:

```asm
.text:00000000004010F8 2C8                 db 0C9h
.text:00000000004010F9 2C8                 db 58h
```

After which we can decompile `CheckSolution` giving us:

```c
__int64 __fastcall CheckSolution(__int64 a1)
{
  __int64 result; // rax@2
  __int64 v2; // rsi@26

  if ( 39342 * *(_DWORD *)(a1 + 44)
     + 21090 * *(_DWORD *)(a1 + 40)
     + 14626 * *(_DWORD *)(a1 + 36)
     + 57693 * *(_DWORD *)(a1 + 32)
     + 16388 * *(_DWORD *)(a1 + 28)
     + 29554 * *(_DWORD *)(a1 + 24)
     + 43166 * *(_DWORD *)(a1 + 20)
     + 50633 * *(_DWORD *)(a1 + 16)
     + 37485 * *(_DWORD *)a1
     - 21621 * *(_DWORD *)(a1 + 4)
     - 1874 * *(_DWORD *)(a1 + 8)
     - 46273 * *(_DWORD *)(a1 + 12)
     + 54757 * *(_DWORD *)(a1 + 48) == 21399379 )
  {
    if ( 22599 * *(_DWORD *)(a1 + 20)
       + 14794 * *(_DWORD *)(a1 + 16)
       + 38962 * *(_DWORD *)(a1 + 12)
       + 50936 * *(_DWORD *)a1
       + 4809 * *(_DWORD *)(a1 + 4)
       - 6019 * *(_DWORD *)(a1 + 8)
       - 837 * *(_DWORD *)(a1 + 24)
       - 36727 * *(_DWORD *)(a1 + 28)
       - 50592 * *(_DWORD *)(a1 + 32)
       - 11829 * *(_DWORD *)(a1 + 36)
       - 20046 * *(_DWORD *)(a1 + 40)
       - 9256 * *(_DWORD *)(a1 + 44)
       + 53228 * *(_DWORD *)(a1 + 48) == 1453872 )
    {
      if ( 5371 * *(_DWORD *)(a1 + 44)
         + 42654 * *(_DWORD *)(a1 + 40)
         + 17702 * *(_DWORD *)(a1 + 32)
         + 26907 * *(_DWORD *)(a1 + 12)
         + -38730 * *(_DWORD *)a1
         + 52943 * *(_DWORD *)(a1 + 4)
         - 16882 * *(_DWORD *)(a1 + 8)
         - 44446 * *(_DWORD *)(a1 + 16)
         - 18601 * *(_DWORD *)(a1 + 20)
         - 65221 * *(_DWORD *)(a1 + 24)
         - 47543 * *(_DWORD *)(a1 + 28)
         - 33910 * *(_DWORD *)(a1 + 36)
         + 11469 * *(_DWORD *)(a1 + 48) == -5074020 )
      {
        if ( 8621 * *(_DWORD *)(a1 + 40)
           + 34805 * *(_DWORD *)(a1 + 28)
           + 10649 * *(_DWORD *)(a1 + 24)
           + 54317 * *(_DWORD *)(a1 + 16)
           + 57747 * *(_DWORD *)a1
           - 23889 * *(_DWORD *)(a1 + 4)
           - 26016 * *(_DWORD *)(a1 + 8)
           - 25170 * *(_DWORD *)(a1 + 12)
           - 32337 * *(_DWORD *)(a1 + 20)
           - 9171 * *(_DWORD *)(a1 + 32)
           - 22855 * *(_DWORD *)(a1 + 36)
           - 634 * *(_DWORD *)(a1 + 44)
           - 11864 * *(_DWORD *)(a1 + 48) == -5467933 )
        {
          if ( 15578 * *(_DWORD *)(a1 + 44)
             + 43186 * *(_DWORD *)(a1 + 36)
             + 28134 * *(_DWORD *)(a1 + 32)
             + 54889 * *(_DWORD *)(a1 + 16)
             + 34670 * *(_DWORD *)(a1 + 12)
             + 43964 * *(_DWORD *)(a1 + 8)
             + -14005 * *(_DWORD *)a1
             + 16323 * *(_DWORD *)(a1 + 4)
             - 6141 * *(_DWORD *)(a1 + 20)
             - 35427 * *(_DWORD *)(a1 + 24)
             - 61977 * *(_DWORD *)(a1 + 28)
             - 59676 * *(_DWORD *)(a1 + 40)
             + 50082 * *(_DWORD *)(a1 + 48) == 7787144 )
          {
            if ( 10305 * *(_DWORD *)(a1 + 44)
               + 29341 * *(_DWORD *)(a1 + 40)
               + 13602 * *(_DWORD *)(a1 + 28)
               + 39603 * *(_DWORD *)(a1 + 24)
               + 13608 * *(_DWORD *)(a1 + 8)
               + -40760 * *(_DWORD *)a1
               - 22014 * *(_DWORD *)(a1 + 4)
               - 4946 * *(_DWORD *)(a1 + 12)
               - 26750 * *(_DWORD *)(a1 + 16)
               - 31708 * *(_DWORD *)(a1 + 20)
               - 59055 * *(_DWORD *)(a1 + 32)
               - 32738 * *(_DWORD *)(a1 + 36)
               - 15650 * *(_DWORD *)(a1 + 48) == -8863847 )
            {
              if ( 16047 * *(_DWORD *)(a1 + 36)
                 + 55241 * *(_DWORD *)(a1 + 28)
                 + 13477 * *(_DWORD *)(a1 + 8)
                 + -47499 * *(_DWORD *)a1
                 + 57856 * *(_DWORD *)(a1 + 4)
                 - 10219 * *(_DWORD *)(a1 + 12)
                 - 5032 * *(_DWORD *)(a1 + 16)
                 - 21039 * *(_DWORD *)(a1 + 20)
                 - 29607 * *(_DWORD *)(a1 + 24)
                 - 6065 * *(_DWORD *)(a1 + 32)
                 - 4554 * *(_DWORD *)(a1 + 40)
                 - 2262 * *(_DWORD *)(a1 + 44)
                 + 18903 * *(_DWORD *)(a1 + 48) == -747805 )
              {
                if ( 41178 * *(_DWORD *)(a1 + 44)
                   + 47909 * *(_DWORD *)(a1 + 28)
                   + 53309 * *(_DWORD *)(a1 + 24)
                   + -65419 * *(_DWORD *)a1
                   + 17175 * *(_DWORD *)(a1 + 4)
                   - 9410 * *(_DWORD *)(a1 + 8)
                   - 22514 * *(_DWORD *)(a1 + 12)
                   - 52377 * *(_DWORD *)(a1 + 16)
                   - 9235 * *(_DWORD *)(a1 + 20)
                   - 59111 * *(_DWORD *)(a1 + 32)
                   - 41289 * *(_DWORD *)(a1 + 36)
                   - 24422 * *(_DWORD *)(a1 + 40)
                   - 23447 * *(_DWORD *)(a1 + 48) == -11379056 )
                {
                  if ( 15699 * *(_DWORD *)(a1 + 40)
                     + 58551 * *(_DWORD *)(a1 + 20)
                     + 46767 * *(_DWORD *)(a1 + 16)
                     + 33381 * *(_DWORD *)(a1 + 12)
                     + 1805 * *(_DWORD *)a1
                     + 4135 * *(_DWORD *)(a1 + 4)
                     - 16900 * *(_DWORD *)(a1 + 8)
                     - 34118 * *(_DWORD *)(a1 + 24)
                     - 44920 * *(_DWORD *)(a1 + 28)
                     - 11933 * *(_DWORD *)(a1 + 32)
                     - 20530 * *(_DWORD *)(a1 + 36)
                     - 36597 * *(_DWORD *)(a1 + 44)
                     + 18231 * *(_DWORD *)(a1 + 48) == -166140 )
                  {
                    if ( 10788 * *(_DWORD *)(a1 + 40)
                       + 18975 * *(_DWORD *)(a1 + 36)
                       + 15033 * *(_DWORD *)(a1 + 32)
                       + 42363 * *(_DWORD *)(a1 + 28)
                       + 47052 * *(_DWORD *)(a1 + 24)
                       + 41284 * *(_DWORD *)(a1 + 12)
                       + -42941 * *(_DWORD *)a1
                       + 61056 * *(_DWORD *)(a1 + 4)
                       - 45169 * *(_DWORD *)(a1 + 8)
                       - 1722 * *(_DWORD *)(a1 + 16)
                       - 26423 * *(_DWORD *)(a1 + 20)
                       - 33319 * *(_DWORD *)(a1 + 44)
                       + 63680 * *(_DWORD *)(a1 + 48) == 9010363 )
                    {
                      if ( 30753 * *(_DWORD *)(a1 + 40)
                         + 22613 * *(_DWORD *)(a1 + 36)
                         + 58786 * *(_DWORD *)(a1 + 28)
                         + 12587 * *(_DWORD *)(a1 + 24)
                         + 12746 * *(_DWORD *)(a1 + 20)
                         + -37085 * *(_DWORD *)a1
                         - 51590 * *(_DWORD *)(a1 + 4)
                         - 17798 * *(_DWORD *)(a1 + 8)
                         - 10127 * *(_DWORD *)(a1 + 12)
                         - 52388 * *(_DWORD *)(a1 + 16)
                         - 8269 * *(_DWORD *)(a1 + 32)
                         - 20853 * *(_DWORD *)(a1 + 44)
                         + 32216 * *(_DWORD *)(a1 + 48) == -4169825 )
                      {
                        if ( 57612 * *(_DWORD *)(a1 + 44)
                           + 47348 * *(_DWORD *)(a1 + 36)
                           + 48719 * *(_DWORD *)(a1 + 32)
                           + 9228 * *(_DWORD *)(a1 + 20)
                           + 65196 * *(_DWORD *)(a1 + 16)
                           + 36650 * *(_DWORD *)a1
                           + 47566 * *(_DWORD *)(a1 + 4)
                           - 33282 * *(_DWORD *)(a1 + 8)
                           - 59180 * *(_DWORD *)(a1 + 12)
                           - 59599 * *(_DWORD *)(a1 + 24)
                           - 62888 * *(_DWORD *)(a1 + 28)
                           - 37592 * *(_DWORD *)(a1 + 40)
                           + 40510 * *(_DWORD *)(a1 + 48) == 4081505 )
                          result = 25633 * *(_DWORD *)(a1 + 44)
                                 + 25252 * *(_DWORD *)(a1 + 36)
                                 + 28153 * *(_DWORD *)(a1 + 32)
                                 + 26517 * *(_DWORD *)(a1 + 28)
                                 + 59511 * *(_DWORD *)(a1 + 16)
                                 + 4102 * *(_DWORD *)(a1 + 12)
                                 + 51735 * *(_DWORD *)a1
                                 + 35879 * *(_DWORD *)(a1 + 4)
                                 - 63890 * *(_DWORD *)(a1 + 8)
                                 - 21386 * *(_DWORD *)(a1 + 20)
                                 - 20769 * *(_DWORD *)(a1 + 24)
                                 - 43789 * *(_DWORD *)(a1 + 40)
                                 + 7314 * *(_DWORD *)(a1 + 48) == 1788229;
                        else
                          result = 0LL;
                      }
                      else
                      {
                        result = 0LL;
                      }
                    }
                    else
                    {
                      result = 0LL;
                    }
                  }
                  else
                  {
                    result = 0LL;
                  }
                }
                else
                {
                  result = 0LL;
                }
              }
              else
              {
                result = 0LL;
              }
            }
            else
            {
              result = 0LL;
            }
          }
          else
          {
            result = 0LL;
          }
        }
        else
        {
          result = 0LL;
        }
      }
      else
      {
        result = 0LL;
      }
    }
    else
    {
      result = 0LL;
    }
  }
  else
  {
    result = 0LL;
  }
  v2 = *MK_FP(__FS__, 40LL) ^ *MK_FP(__FS__, 40LL);
  return result;
}
```

We turn this series of constraints on our input values into a [series of constraints for z3](solution/babyre_crack.py) which will solve them for us and give us the flag:

```python
from z3 import *

def solve_check():
  l = []
  for i in xrange(0, 13):
    # Add unknown 
    l.append(BitVec(i, 32))

  s = Solver()
  for i in xrange(0, 13):
    # add ASCII-printability constraints
    s.add(l[i] >= 0x20, l[i] <= 0x7E)

  # Add check constraints
  s.add(39342 * l[11] + 21090 * l[10] + 14626 * l[9] + 57693 * l[8] + 16388 * l[7] + 29554 * l[6] + 43166 * l[5] + 50633 * l[4] + 37485 * l[0] - 21621 * l[1] - 1874 * l[2] - 46273 * l[3] + 54757 * l[12] == 21399379)
  s.add(22599 * l[5] + 14794 * l[4] + 38962 * l[3] + 50936 * l[0] + 4809 * l[1] - 6019 * l[2] - 837 * l[6] - 36727 * l[7] - 50592 * l[8] - 11829 * l[9] - 20046 * l[10] - 9256 * l[11] + 53228 * l[12] == 1453872)
  s.add(5371 * l[11] + 42654 * l[10] + 17702 * l[8] + 26907 * l[3] + -38730 * l[0] + 52943 * l[1] - 16882 * l[2] - 44446 * l[4] - 18601 * l[5] - 65221 * l[6] - 47543 * l[7] - 33910 * l[9] + 11469 * l[12] == -5074020)
  s.add(8621 * l[10] + 34805 * l[7] + 10649 * l[6] + 54317 * l[4] + 57747 * l[0] - 23889 * l[1] - 26016 * l[2] - 25170 * l[3] - 32337 * l[5] - 9171 * l[8] - 22855 * l[9] - 634 * l[11] - 11864 * l[12] == -5467933)
  s.add(15578 * l[11] + 43186 * l[9] + 28134 * l[8] + 54889 * l[4] + 34670 * l[3] + 43964 * l[2] + -14005 * l[0] + 16323 * l[1] - 6141 * l[5] - 35427 * l[6] - 61977 * l[7] - 59676 * l[10] + 50082 * l[12] == 7787144)
  s.add(10305 * l[11] + 29341 * l[10] + 13602 * l[7] + 39603 * l[6] + 13608 * l[2] + -40760 * l[0] - 22014 * l[1] - 4946 * l[3] - 26750 * l[4] - 31708 * l[5] - 59055 * l[8] - 32738 * l[9] - 15650 * l[12] == -8863847)
  s.add(16047 * l[9] + 55241 * l[7] + 13477 * l[2] + -47499 * l[0] + 57856 * l[1] - 10219 * l[3] - 5032 * l[4] - 21039 * l[5] - 29607 * l[6] - 6065 * l[8] - 4554 * l[10] - 2262 * l[11] + 18903 * l[12] == -747805)
  s.add(41178 * l[11] + 47909 * l[7] + 53309 * l[6] + -65419 * l[0] + 17175 * l[1] - 9410 * l[2] - 22514 * l[3] - 52377 * l[4] - 9235 * l[5] - 59111 * l[8] - 41289 * l[9] - 24422 * l[10] - 23447 * l[12] == -11379056)
  s.add(15699 * l[10] + 58551 * l[5] + 46767 * l[4] + 33381 * l[3] + 1805 * l[0] + 4135 * l[1] - 16900 * l[2] - 34118 * l[6] - 44920 * l[7] - 11933 * l[8] - 20530 * l[9] - 36597 * l[11] + 18231 * l[12] == -166140)
  s.add(10788 * l[10] + 18975 * l[9] + 15033 * l[8] + 42363 * l[7] + 47052 * l[6] + 41284 * l[3] + -42941 * l[0] + 61056 * l[1] - 45169 * l[2] - 1722 * l[4] - 26423 * l[5] - 33319 * l[11] + 63680 * l[12] == 9010363)
  s.add(30753 * l[10] + 22613 * l[9] + 58786 * l[7] + 12587 * l[6] + 12746 * l[5] + -37085 * l[0] - 51590 * l[1] - 17798 * l[2] - 10127 * l[3] - 52388 * l[4] - 8269 * l[8] - 20853 * l[11] + 32216 * l[12] == -4169825)
  s.add(57612 * l[11] + 47348 * l[9] + 48719 * l[8] + 9228 * l[5] + 65196 * l[4] + 36650 * l[0] + 47566 * l[1] - 33282 * l[2] - 59180 * l[3] - 59599 * l[6] - 62888 * l[7] - 37592 * l[10] + 40510 * l[12] == 4081505)
  s.add(25633 * l[11] + 25252 * l[9] + 28153 * l[8] + 26517 * l[7] + 59511 * l[4] + 4102 * l[3] + 51735 * l[0] + 35879 * l[1] - 63890 * l[2] - 21386 * l[5] - 20769 * l[6] - 43789 * l[10] + 7314 * l[12] == 1788229)

  # Check if problem is satisfiable before trying to solve it
  if(s.check() == sat):
    print "[+] Problem is SAT :) solving..."
    # Now solve it
    sol_model = s.model()
    
    # Convert solution to string
    sol = ""
    for i in xrange(0, 13):
      sol += chr(sol_model[l[i]].as_long())
    return sol
  else:
    return False

print "[*] Setting up SAT constraints..."
flag = solve_check()
if (flag):
  print "[+] Got flag: [%s]" % flag
```

Which gives us:

```bash
$ python babyre_crack.py
[*] Setting up SAT constraints...
[+] Problem is SAT :) solving...
[+] Got flag: [Math is hard!]
```