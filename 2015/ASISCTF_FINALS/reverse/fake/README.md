# ASISCTF Finals 2015: Fake

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASISCTF Finals 2015 | Fake | Reversing |    150 |

**Description:**
>*Find the flag in this [file](challenge/fake).*

----------
## Write-up

We're dealing with another 64-bit ELF keygen challenge this time consisting of a rather small binary with the following pseudocode:

```c
__int64 __fastcall main_routine(signed int a1, __int64 a2)
{
  __int64 v2; // r8@1
  __int64 v4; // [sp+0h] [bp-38h]@3
  __int64 v5; // [sp+8h] [bp-30h]@3
  __int64 v6; // [sp+10h] [bp-28h]@3
  __int64 v7; // [sp+18h] [bp-20h]@3
  __int64 v8; // [sp+20h] [bp-18h]@3

  v2 = 0LL;
  if ( a1 > 1 )
    v2 = strtol(*(const char **)(a2 + 8), 0LL, 10);
  v4 = 0x3CC6C7B7 * v2;
  v5 = 0x981DDEC9AB2D9LL
     * ((v2 >> 19)
      - 0xB15 * (((signed __int64)((unsigned __int128)(0x5C66DE85BAE10C8BLL * (v2 >> 19)) >> 64) >> 10) - (v2 >> 63)))
     * ((v2 >> 19)
      - 0x23 * (((signed __int64)((unsigned __int128)(0xEA0EA0EA0EA0EA1LL * (v2 >> 19)) >> 64) >> 1) - (v2 >> 63)))
     * ((v2 >> 19)
      - 0x21 * (((signed __int64)((unsigned __int128)(0xF83E0F83E0F83E1LL * (v2 >> 19)) >> 64) >> 1) - (v2 >> 63)));
  v6 = ((v2 >> 19)
      - 0x25AB * (((signed __int64)((unsigned __int128)(0x1B2F55AB6B39F429LL * (v2 >> 19)) >> 64) >> 10) - (v2 >> 63)))
     * 0x148E0E2774AE66LL
     * ((v2 >> 19)
      - 0xA7 * (((signed __int64)((unsigned __int128)(0x621B97C2AEC12653LL * (v2 >> 19)) >> 64) >> 6) - (v2 >> 63)));
  v7 = ((v2 >> 19)
      - 0x101 * (((signed __int64)((unsigned __int128)(0x7F807F807F807F81LL * (v2 >> 19)) >> 64) >> 7) - (v2 >> 63)))
     * 0x25FB3FE64A952LL
     * ((v2 >> 19)
      - 0x37 * (((signed __int64)((unsigned __int128)(0x4A7904A7904A7905LL * (v2 >> 19)) >> 64) >> 4) - (v2 >> 63)));
  v8 = ((v2 >> 19)
      - 0xBC8F * (((signed __int64)((unsigned __int128)(0x15B90241024BDECDLL * (v2 >> 19)) >> 64) >> 12) - (v2 >> 63)))
     * 0x246DC95E05ELL
     * ((v2 >> 19)
      - 0x17
      * (((signed __int64)((v2 >> 19) + ((unsigned __int128)(0x0B21642C8590B2165LL * (v2 >> 19)) >> 64)) >> 4)
       - (v2 >> 63)));
  puts((const char *)&v4);
  return 0LL;
}
```

So we have a 'mystery routine' which converts our numeric input into our flag (it has to since our input can only be numeric and a single `puts` call is all we have for output). The routine, converted to python by hand, does this as follows:

```python
def mystery(v2):  
  int64 =  2**64
  int128 = 2**128

  v4 = (0x3CC6C7B7 * v2) % int64

  a = ((v2 >> 19) - (0xB15 * (( ((((0x5C66DE85BAE10C8B * (v2 >> 19)) % int128) >> 64) % int64) >> 10) - (v2 >> 63))))
  b = ((v2 >> 19) - (0x23 * (( ((((0xEA0EA0EA0EA0EA1 * (v2 >> 19)) % int128) >> 64) % int64) >> 1) - (v2 >> 63))))
  c = ((v2 >> 19) - (0x21 * (( ((((0xF83E0F83E0F83E1 * (v2 >> 19)) % int128) >> 64) % int64) >> 1) - (v2 >> 63))))
  
  v5 = (0x981DDEC9AB2D9 * a * b * c) % int64

  a = ((v2 >> 19) - (0x25AB * (( ((((0x1B2F55AB6B39F429 * (v2 >> 19)) % int128) >> 64) % int64) >> 10) - (v2 >> 63))))
  b = 0x148E0E2774AE66
  c = ((v2 >> 19) - (0xA7 * (( ((((0x621B97C2AEC12653 * (v2 >> 19)) % int128) >> 64) % int64) >> 6) - (v2 >> 63))))

  v6 = (a * b * c) % int64

  a = ((v2 >> 19) - (0x101 * (( ((((0x7F807F807F807F81 * (v2 >> 19)) % int128) >> 64) % int64) >> 7) - (v2 >> 63))))
  b = 0x25FB3FE64A952
  c = ((v2 >> 19) - (0x37 * (( ((((0x4A7904A7904A7905 * (v2 >> 19)) % int128) >> 64) % int64) >> 4) - (v2 >> 63))))

  v7 = (a * b * c) % int64

  a = ((v2 >> 19) - (0xBC8F * (( ((((0x15B90241024BDECD * (v2 >> 19)) % int128) >> 64) % int64) >> 12) - (v2 >> 63))))
  b = 0x246DC95E05E
  c = ((v2 >> 19) - (0x17 * (( ((((0x0B21642C8590B2165 * (v2 >> 19)) % int128) >> 64) % int64) >> 4) - (v2 >> 63))))

  v8 = (a * b * c) % int64

  y = [v4, v5, v6, v7, v8]

  z = "".join([pack('<Q', x) for x in y])

  return z[0:z.find("\x00")]
```

As we can see the first 64 bits of output are derived exclusively from a single modular multiplication: `(0x3CC6C7B7 * v2) % int64`. We know flags are of the format ASIS{....} where the inner part is 32 bits of lowercase hex characters. Given that we know the first 5 characters of our ouput "ASIS{" = "\x41\x53\x49\x53\x7B" followed by 3 unknown bytes which translates to the little-endian QWORD of v4 = 0x??????7b53495341 we can try to determine v2 by solving the modular multiplication for the 3 unknown bytes (lazily using Z3):

```python
def solve():
  s = Solver()

  v2 = BitVec('v2', 64)

  s.add((((0x3CC6C7B7 * v2) % (2**64)) & 0x000000ffffffffff) == 0x7b53495341)

  # Check if problem is satisfiable before trying to solve it
  if(s.check() == sat):
    return s.model()[v2]
  else:
    raise Exception("[-] Problem unsatisfiable :(")
```

This gives us our numeric input 25313971399 which when passed as argument to the binary gives us the flag:

```bash
$ ./fake 25313971399
ASIS{f5f7af556bd6973bd6f2687280a243d9}
```