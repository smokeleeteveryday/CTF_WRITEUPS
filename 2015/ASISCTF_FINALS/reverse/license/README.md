# ASISCTF Finals 2015: License

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASISCTF Finals 2015 | License | Reversing |    125 |

**Description:**
>*Find the flag in this [file](challenge/license).*

----------
## Write-up

The challenge binary in question is a 64-bit ELF binary which checks a license file with a series of constraints and outputs the flag (derived in part from the license file) if it is correct.

Let's take a look at its pseudo-code:

```c
__int64 main_routine()
{
  v75 = *MK_FP(__FS__, 40LL);
  v0 = fopen("_a\nb\tc_", "rb");
  v1 = v0;
  JUMPOUT(v0, 0LL, "+¯\x10@");
  fseek(v0, 0LL, 2);
  v2 = 68;
  v3 = ftell(v1);
  rewind(v1);
  v4 = calloc(1uLL, v3 + 1);
  v5 = (__int64)v4;
  if ( v4 )
  {
    LOBYTE(v2) = 58;
    if ( fread(v4, v3, 1uLL, v1) == 1 )
    {
      fclose(v1);
      if ( 0xFFFFFFFFFFFF4F4DLL * v3 * v3 * v3 * v3
         + 0xFFFFFFFFFFFFFB18LL * v3 * v3 * v3
         + 0x3838 * v3 * v3
         + 0xFFFFFFFFFFFF168ELL * v3
         - 0x1C5F164EF8CLL
         + 0xACD2 * v3 * v3 * v3 * v3 * v3 )
      {
        LOBYTE(v2) = 0;
        LODWORD(v15) = output(0x6020C0LL, 0x4010F3LL);// wrong formatted key file
        std::endl<char,std::char_traits<char>>(v15);
      }
      else
      {
        v31 = v5;
        v7 = v5;
        v8 = 1;
        while ( v3 > v7 - v5 )
        {
          v9 = v7 + 1;
          if ( *(_BYTE *)v7 == 10 )
          {
            v10 = v8++;
            *(&v31 + v10) = v9;
          }
          v7 = v9;
        }
        v11 = (v3 - (v8 - 1)) / v8;
        v12 = (v3 - (v8 - 1)) / v8;
        some_int = (v3 - (v8 - 1)) / v8;
        if ( (unsigned __int64)(5 * v11) > 0x5B || v11 <= 0 )
        {
          v2 = 32;
          LODWORD(v14) = output(0x6020C0LL, 0x4010F3LL);// wrong formatted key file
          std::endl<char,std::char_traits<char>>(v14);
        }
        else if ( v8 == 5 )
        {
          v36 = 0x35;
          v37 = 0x3F;
          v16 = 0LL;
          v38 = 112;
          v39 = 0x14;
          v40 = 0x2E;
          v41 = 0x79;
          v42 = 0x6E;
          v43 = 0x2F;
          v44 = 0x44;
          v45 = 0xD;
          v46 = 0x1B;
          v47 = 0x3F;
          v48 = 0x3C;
          v49 = 0x3E;
          v50 = 0x1C;
          v51 = 0x2D;
          v52 = 9;
          v53 = 0x24;
          v54 = 0x25;
          v55 = 0xB;
          v56 = 0x3B;
          v57 = 0xE;
          v58 = 0x5E;
          v59 = 0x4D;
          v60 = 0x24;
          v61 = 0x1A;
          v62 = 0x67;
          v63 = 0x3F;
          v64 = 0x50;
          v65 = 0x5A;
          v66 = 0x60;
          v67 = 4;
          v68 = 0x4A;
          v69 = 0x16;
          v17 = v32;
          v18 = v31;
          v70 = 0x33;
          v71 = 0x65;
          v72 = 0x30;
          v73 = 0x7D;
          do
          {
            s1[v16] = *(_BYTE *)(v18 + v16) ^ *(_BYTE *)(v17 + v16);
            ++v16;
          }
          while ( v12 > (signed int)v16 );
          if ( memcmp(
                 s1,
                 "iKWoZLVc4LTyGrCRedPhfEnihgyGxWrCGjvi37pnPGh2f1DJKEcQZMDlVvZpEHHzUfd4VvlMzRDINqBk;1srRfRvvUW",
                 v11) )
            goto LABEL_39;
          v19 = v34;
          v20 = 0LL;
          do
          {
            s1[v20] = *(_BYTE *)(v17 + v20) ^ *(_BYTE *)(v19 + v20) ^ 0x23;
            ++v20;
          }
          while ( v12 > (signed int)v20 );
          v30 = (const void *)v19;
          if ( memcmp(s1, &aIkwozlvc4ltygr[v11], v11) )
            goto LABEL_39;
          v21 = v33;
          v22 = 0LL;
          do
          {
            s1[v22] = *((_BYTE *)v30 + v22) ^ *(_BYTE *)(v21 + v22);
            ++v22;
          }
          while ( v12 > (signed int)v22 );
          if ( memcmp(s1, (const void *)(2 * v11 + 0x401120LL), v11) )
            goto LABEL_39;
          v23 = v35;
          v24 = 0LL;
          do
          {
            s1[v24] = *((_BYTE *)v30 + v24) ^ *(_BYTE *)(v23 + v24) ^ 0x23;
            ++v24;
          }
          while ( v12 > (signed int)v24 );
          v25 = 0LL;
          do
          {
            s1[v25] ^= *(_BYTE *)(v21 + v25);
            ++v25;
          }
          while ( v12 > (signed int)v25 );
          if ( !memcmp(s1, (const void *)(3 * v11 + 4198688LL), v11)
            && (v2 = memcmp(v30, (const void *)(4 * v11 + 4198688LL), v11)) == 0 )
          {
            v26 = 0LL;
            do
            {
              if ( v3 > v26 )
                *(&v36 + v26) ^= *(_BYTE *)(v5 + v26);
              ++v26;
            }
            while ( v26 != 38 );
            LODWORD(v27) = output(6299840LL, 0x401180LL);// program successfully registered to 
            LODWORD(v28) = output(v27, &v36);
            std::endl<char,std::char_traits<char>>(v28);
          }
          else
          {
LABEL_39:
            v2 = 0;
            LODWORD(v29) = output(6299840LL, 4198668LL);// key file not found!
            std::endl<char,std::char_traits<char>>(v29);
          }
        }
        else
        {
          v2 = 23;
          LODWORD(v13) = output(0x6020C0LL, 0x4010F3LL);// wrong formatted key file
          std::endl<char,std::char_traits<char>>(v13);
        }
      }
    }
  }
  return (unsigned int)v2;
}
```

Reverse-engineering the initial few lines reveals the license needs to be named "_a\nb\tc_" and needs to be 34 bytes long as per the solution of:

```python
((0xACD2 * v3*v3*v3*v3*v3) + (0xFFFFFFFFFFFF4F4D * v3*v3*v3*v3) + (0xFFFFFFFFFFFFFB18 * v3*v3*v3) + (0x3838 * v3*v3) + (0xFFFFFFFFFFFF168E * v3)) == 0x1C5F164EF8C
```

The next lines of code:

```c
 v31 = v5;
        v7 = v5;
        v8 = 1;
        while ( v3 > v7 - v5 )
        {
          v9 = v7 + 1;
          if ( *(_BYTE *)v7 == 0x0A )
          {
            v10 = v8++;
            *(&v31 + v10) = v9;
          }
          v7 = v9;
        }
        v11 = (v3 - (v8 - 1)) / v8;
        v12 = (v3 - (v8 - 1)) / v8;
        some_int = (v3 - (v8 - 1)) / v8;
        if ( (unsigned __int64)(5 * v11) > 0x5B || v11 <= 0 )
        {
          v2 = 32;
          LODWORD(v14) = output(0x6020C0LL, 0x4010F3LL);// wrong formatted key file
          std::endl<char,std::char_traits<char>>(v14);
        }
        else if ( v8 == 5 )
        {
```

Divide the program into newline-seperated (0x0A = "\n") chunks (of which there have to be 5) each of which is 6 bytes long. These lines are then checked against a whole series of XOR-based constraints over segments of the hardcoded buffer "iKWoZLVc4LTyGrCRedPhfEnihgyGxWrCGjvi37pnPGh2f1DJKEcQZMDlVvZpEHHzUfd4VvlMzRDINqBk;1srRfRvvUW" and finally used as a XOR key to decode an internal buffer into the flag (which will be output as the 'registration user'):

```c
            do
            {
              if ( v3 > v26 )
                *(&v36 + v26) ^= *(_BYTE *)(v5 + v26);
              ++v26;
            }
            while ( v26 != 38 );
            LODWORD(v27) = output(6299840LL, 0x401180LL);// program successfully registered to 
            LODWORD(v28) = output(v27, &v36);
            std::endl<char,std::char_traits<char>>(v28);
```

We encoded the series of constraints into a satisfiability problem using Z3 giving us the [following license generation script](solution/gen_license.py):

```python
#!/usr/bin/env python
#
# ASISCTF Finals 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from z3 import *

def gen_license():
  filelen = 34
  filename = "_a\nb\tc_"

  f = open(filename, "wb")
  content = ""

  x = ["iKWoZL", "Vc4LTy", "GrCRed", "PhfEni", "hgyGxW"]

  s = Solver()

  lines = [None]*(5*10 + 6)
  for i in xrange(5):
    for j in xrange(6):
      lines[(i*10)+j] = BitVec((i*10)+j, 8)

  for j in xrange(6):
    s.add(lines[(0*10)+j] ^ lines[(1*10)+j] == ord(x[0][j]))
    s.add(lines[(1*10)+j] ^ lines[(3*10)+j] ^ 0x23 == ord(x[1][j]))
    s.add(lines[(3*10)+j] ^ lines[(2*10)+j] == ord(x[2][j]))
    s.add(lines[(3*10)+j] ^ lines[(4*10)+j] ^ lines[(2*10)+j] ^ 0x23 == ord(x[3][j]))
    s.add(lines[(3*10)+j] == ord(x[4][j]))

  linez = []

  # Check if problem is satisfiable before trying to solve it
  if(s.check() == sat):
    print "[+] Problem satisfiable, generating license :)"
    sol_model = s.model()
    for i in xrange(5):
      s = ""
      for j in xrange(6):
        s += chr(sol_model[lines[(i*10)+j]].as_long())

      linez.append(s)
  else:
    raise Exception("[-] Problem unsatisfiable, could not generate license :(")

  content += linez[0] + chr(10)
  content += linez[1] + chr(10)
  content += linez[2] + chr(10)
  content += linez[3] + chr(10)
  content += linez[4]

  assert(len(content) == filelen)

  f.write(content)
  f.close()

  return

gen_license()
```

Using it to generate a license and then run the program yields the following:

```bash
$ ./gen_license.py 
[+] Problem satisfiable, generating license :)
$ ./license 
program successfully registered to ASIS{8d2cc30143831881f94cb05dcf0b83e0}
```