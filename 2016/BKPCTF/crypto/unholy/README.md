# BKPCTF 2016: unholy

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| BKPCTF | unholy | Reversing | 4 |

### Description
> python or ruby? why not both! [https://s3.amazonaws.com/bostonkeyparty/2016/9c2b8593c64486de25698fcece7c12fa0679a224.tar.gz](challenge)

## Write-up

We are given a ruby script and an accompanying dynamic library which together validate a flag:

```ruby
require_relative 'unholy'
include UnHoly
python_hi
puts ruby_hi
puts "Programming Skills: PRIMARILY RUBY AND PYTHON BUT I CAN USE ANY TYPE OF GEM TO CONTROL ANY TYPE OF SNAKE"
puts "give me your flag"
flag = gets.chomp!
arr = flag.unpack("V*")
is_key_correct? arr
```

We can see our input being consumed as a string and converted to an array of 4-byte DWORD values which are passed to `is_key_correct`. Let's take a look at `is_key_correct` in `unholy.so`:

```
signed __int64 __fastcall method_check_key(VALUE self, VALUE arr)
{
  unsigned __int64 v2; // rax@1
  int v3; // eax@2
  __int64 index; // r12@5
  __int64 arval; // rax@6
  int v6; // eax@7
  __int64 mindex; // rdi@10
  unsigned int sum; // er8@11
  __int64 v9; // rdx@11
  __int64 v10; // rax@11
  uint32_t v11; // er9@12
  __int64 v12; // rbx@16
  uint32_t key[4]; // [sp+8h] [bp-13E0h]@4
  uint32_t matrix[10]; // [sp+18h] [bp-13D0h]@9
  char stacker[5000]; // [sp+40h] [bp-13A8h]@15
  __int64 v17; // [sp+13C8h] [bp-20h]@1

  v17 = *MK_FP(__FS__, 40LL);
  v2 = *(_QWORD *)arr;
  if ( BYTE1(v2) & 0x20 )
    v3 = (v2 >> 15) & 3;
  else
    v3 = *(_DWORD *)(arr + 16);
  key[0] = 'tahw';
  key[1] = 'iogs';
  key[2] = 'nogn';
  key[3] = 'ereh';
  if ( v3 == 9 )
  {
    index = 0LL;
    do
    {
      LODWORD(arval) = rb_ary_entry(arr, index);
      if ( arval & 1 )
        v6 = rb_fix2int(arval);
      else
        v6 = rb_num2int(arval);
      matrix[index++] = v6;
    }
    while ( index != 9 );
    matrix[9] = 0x61735320;
    mindex = 0LL;
    do
    {
      sum = 0;
      LODWORD(v9) = *(_QWORD *)&matrix[mindex];
      v10 = *(_QWORD *)&matrix[mindex] >> 32;
      do
      {
        v11 = sum + key[(unsigned __int64)(sum & 3)];
        sum -= 0x61C88647;
        v9 = (v11 ^ ((16 * (_DWORD)v10 ^ ((unsigned int)v10 >> 5)) + (_DWORD)v10)) + (unsigned int)v9;
        v10 = ((sum + key[(unsigned __int64)((sum >> 11) & 3)]) ^ ((16 * (_DWORD)v9 ^ ((unsigned int)v9 >> 5))
                                                                 + (_DWORD)v9))
            + (unsigned int)v10;
      }
      while ( sum != 0xC6EF3720 );
      *(_QWORD *)&matrix[mindex] = v9 | (v10 << 32);
      mindex += 2LL;
    }
    while ( mindex != 0xA );
    if ( matrix[9] == 0x4DE3F9FD )
    {
      __sprintf_chk(
        stacker,
        1LL,
        5000LL,
        "exec \"\"\"\\nimport struct\\ne=range\\nI=len\\nimport sys\\nF=sys.exit\\nX=[[%d,%d,%d],[%d,%d,%d],[%d,%d,%d]]\\"
        "nY = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]\\nn=[5034563854941868"
        ",252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-36335073107"
        "95117,195138776204250759,-34639402662163370450]\\ny=[[0,0,0],[0,0,0],[0,0,0]]\\nA=[0,0,0,0,0,0,0,0,0]\\nfor i in"
        " e(I(X)):\\n for j in e(I(Y[0])):\\n  for k in e(I(Y)):\\n   y[i][j]+=X[i][k]*Y[k][j]\\nc=0\\nfor r in y:\\n for"
        " x in r:\\n  if x!=n[c]:\\n   print \"dang...\"\\n   F(47)\\n  c=c+1\\nprint \":)\"\\n\"\"\"",
        matrix[0],
        matrix[1]);
      Py_Initialize(stacker);
      PyRun_SimpleStringFlags(stacker, 0LL);
      Py_Finalize(stacker, 0LL);
    }
  }
  v12 = *MK_FP(__FS__, 40LL) ^ v17;
  return 8LL;
}
```

The above function performs some checks on the ruby array structure (eg. checking whether it has 9 entries, hinting at an expected input size of 9*4 = 36) before ordering the ruby array into a 3x3 matrix structure (represented as a 1-dimensional array to which 0x61735320 is appended). This matrix is then pulled through an as-of-yet unidentified series of arithmetic operations which then checks whether the final DWORD in the in-place permutated matrix is 0x4DE3F9FD. If so, the first 9 fields of the 3x3 matrix are format-printed to an embedded python program which checks whether the resulting matrix (after some matrix arithmetic) matches an embedded verification matrix.

This last bit allows us to work our way back to the input from the verification matrix by simply taking the input matrix `X` as an unknown and lazily represent the problem as a constraint-based programming problem which we can feed to eg. Z3. The resulting matrix will be the expected output of the 'mystery' arithmetic routine which we will have to invert to obtain our actual flag. A keen crypto eye will have already spotted the constants 0xC6EF3720 and 0x61C88647 which are, respectively, the sum and delta values of the XTEA block cipher. Since 0x61C88647 is the 2's complement representation of -0x9E3779B9 this effectively makes sum -= 0x61C88647 identical to sum += 0x9E3779B9 indicating we are dealing with the XTEA cipher encrypting our flag in ECB mode. A little bit of further reverse-engineering can spot the hardcoded XTEA key `whatsgoingonhere`.

So we are left with finding the input matrix `X` and decrypting it using XTEA-ECB with key `whatsgoingonhere` which our [solution script](solution/unholy_crack.py) does as follows:

```python
#!/usr/bin/python
#
# BKPCTF 2016
# unholy (REVERSING/4)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import xtea
from z3 import *
from struct import unpack, pack

def get_blocks(data, block_size):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def solve_matrix_system():
    s = Solver()

    Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]
    n = [[5034563854941868,252734795015555591,55088063485350767967],[-2770438152229037,142904135684288795,-33469734302639376803],[-3633507310795117,195138776204250759,-34639402662163370450]]
    A = [0,0,0,0,0,0,0,0,0]

    X = [[BitVec(0,32), BitVec(1,32), BitVec(2,32)], [BitVec(3,32), BitVec(4,32), BitVec(5,32)], [BitVec(6,32), BitVec(7,32), BitVec(8,32)]]

    for i in xrange(3):
        for j in xrange(len(Y[0])):
            s.add(n[i][j] == ((X[i][0]*Y[0][j]) + (X[i][1]*Y[1][j]) + (X[i][2]*Y[2][j])))

    if (s.check() == sat):
        print "[*] Matrix problem satisfiable, solving..."
        sol_model = s.model()
        R = [[0,0,0], [0,0,0], [0,0,0]]
        for i in xrange(3):
            for j in xrange(3):
                R[i][j] = sol_model[X[i][j]].as_long()
        return R
    else:
        print "[-] Matrix problem unsatisfiable :("
        return []

def xtea_decrypt_matrix(matrix):
    # whatsgoingonhere
    key = [0x74616877, 0x696F6773, 0x6E6F676E, 0x65726568]
    k = ''.join([pack('>I', x) for x in key])

    m = []

    # convert python matrix
    for i in xrange(3):
        for j in xrange(3):
            m.append(matrix[i][j])

    # last ciphertext block used for validation
    m.append(0x4DE3F9FD)
    # known plaintext last block for validation
    kp = pack('<I', 0x61735320)

    c = ''.join([pack('>I', x) for x in m])
    cipher = xtea.new(k, mode=xtea.MODE_ECB)
    p1 = cipher.decrypt(c)

    # reorder blocks
    blocks = get_blocks(p1, 4)
    p1 = ''.join([b[::-1] for b in blocks])

    # validate plaintext
    if(p1[-len(kp):] == kp):
        return p1
    else:
        return ''

matrix = solve_matrix_system()
print "[+] Matrix solution:", matrix
p = xtea_decrypt_matrix(matrix)
if (p != ''):
    print "[+] Found correct plaintext: [%s]" % p
else:
    print "[-] Incorrect plaintext :("
```

Which gives us:

```bash
$ ./unholy_crack.py
[*] Matrix problem satisfiable, solving...
[+] Matrix solution: [[2990080719L, 722035088, 1368334760], [1473172750, 412774077, 3386066071L], [3804000291L, 563111828, 3342378109L]]
[+] Found correct plaintext: [BKPCTF{hmmm _why did i even do this} Ssa]
```