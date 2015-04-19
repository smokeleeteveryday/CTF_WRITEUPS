# Plaid CTF 2015: Clifford

**Category:** Clifford
**Points:** 100
**Description:** 

>["It's a keygen problem"](challenge/clifford.elf)

## Write-up

We start by first checking the binary:

>```bash
>$ file clifford
> clifford: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xd8f66a63ac7b9dd7fe328bf9fc8852b497064e9f, stripped
>```

A stripped 64-bit ELF binary. Let's load it up in IDA and decompile it (function and variable names added for clarity):

>```c
>void __noreturn entrysub()
>{
>  __int64 v0; // rbx@6
>  int v1; // [sp+0h] [bp-70h]@23
>  int v2; // [sp+4h] [bp-6Ch]@23
>  int v3; // [sp+8h] [bp-68h]@23
>  int v4; // [sp+Ch] [bp-64h]@23
>  int v5; // [sp+10h] [bp-60h]@23
>  int v6; // [sp+14h] [bp-5Ch]@23
>  int v7; // [sp+18h] [bp-58h]@23
>  int v8; // [sp+1Ch] [bp-54h]@23
>  int v9; // [sp+20h] [bp-50h]@23
>  int v10; // [sp+24h] [bp-4Ch]@23
>  __int64 input; // [sp+30h] [bp-40h]@5
>  int order; // [sp+38h] [bp-38h]@1
>  int i; // [sp+3Ch] [bp-34h]@5
>  int j; // [sp+40h] [bp-30h]@8
>  int k; // [sp+44h] [bp-2Ch]@9
>  int l; // [sp+48h] [bp-28h]@14
>  int m; // [sp+4Ch] [bp-24h]@15
>  int n_ctr; // [sp+50h] [bp-20h]@23
>  int v19; // [sp+54h] [bp-1Ch]@8
>  int v20; // [sp+58h] [bp-18h]@15
>  int v21; // [sp+5Ch] [bp-14h]@15
>
>  puts("What order?");
>  __isoc99_scanf(4198892LL, &order);
>  if ( order <= 1 || order > 10 )
>  {
>    puts("Sorry, that's not a good order.");
>    exit(0);
>  }
>  input = (__int64)calloc(2 * order - 1, 8uLL);
>  for ( i = 0; 2 * order - 1 > i; ++i )
>  {
>    v0 = input + 8LL * i;
>    *(_QWORD *)v0 = calloc(i + order, 4uLL);
>  }
>  v19 = 3 * order * order + -3 * order + 1;
>  puts("Input numbers.");
>  for ( j = 0; j < order; ++j )
>  {
>    for ( k = 0; j + order > k; ++k )
>      __isoc99_scanf(4198892LL, *(_QWORD *)(input + 8LL * j) + 4LL * k);
>  }
>  for ( l = order; 2 * order - 1 > l; ++l )
>  {
>    v20 = 2 * order - 1 + ~(l - order);
>    v21 = l - order + 1;
>    for ( m = 0; m < v20; ++m )
>      __isoc99_scanf(4198892LL, *(_QWORD *)(input + 8LL * l) + 4LL * (m + v21));
>  }
>  puts("Got input! Verifying...");
>  if ( !(unsigned int)crypto1(input, order) )
>  {
>    puts("Sorry, incorrect!");
>    exit(0);
>  }
>  v1 = -1089151902;
>  v2 = 34416792;
>  v3 = -110388501;
>  v4 = -1513521000;
>  v5 = 1721500667;
>  v6 = 1493041700;
>  v7 = -219333338;
>  v8 = 1148696600;
>  v9 = 1201108895;
>  v10 = -392044752;
>  puts("Success!");
>  crypto2(input, order);
>  for ( n_ctr = 0; n_ctr <= 4; ++n_ctr )
>    crypto3(0x20u, (__int64)(&v1 + 2 * n_ctr), 6299728LL);
>  printf("Your flag is: %s\n", &v1, *(_QWORD *)&v1, *(_QWORD *)&v3, *(_QWORD *)&v5, *(_QWORD *)&v7, *(_QWORD *)&v9);
>  exit(0);
>}
>```

Ok so we can see that the binary asks us for an 'order', does some memory allocation and initialization and asks us for a list of input values after which it calls 'crypto1' on our supplied input and if it's correct it will call 'crypto2' and 'crypto3' with our input and output the flag. In order to save us some time we don't need to reverse engineer crypto2 and crypto3 since a quick look at them reveals they simply permutate our supplied input and use it to decrypt the flag buffer. Let's first reverse engineer the allocation and initialization process a bit and make a python equivalent to toy with so we can see what happens:

>```python
>print "What order?"
>
>order = int(raw_input())
>
>if ((order <= 1) or (order > 10)):
>	print "Sorry, that's not a good order."
>	exit()
>
>#input = (__int64)calloc(2 * order - 1, 8uLL);
>#(2*order-1) elements of 8 bytes each
>inputnum = [[]]*(2 * order - 1)
>
>for i in xrange(0, (2*order-1)):
>	#*(_QWORD *)v0 = calloc(i + order, 4uLL);
>	#(i + order) elements of 4 bytes each
>	inputnum[i] = [0]*(i + order)
>
>v19 = 3 * order * order + -3 * order + 1
>
>print "Input numbers."
>
>for j in xrange(0, order):
>	for k in xrange(0, (j+order)):
>		inputnum[j][k] = int(raw_input())
>
>#last rows will be padded with same amount of 0s on each side
>for l in xrange(order, (2*order-1)):
>	#v20 is the number of elements that will be placed in padded row
>	v20 = (2*order) - 1 + ~(l-order)
>	#v21 is the number of padding 0s (and hence the start of where the content will be written to)
>	v21 = l - order + 1
>	for m in xrange(0, v20):
>		inputnum[l][m + v21] = int(raw_input())
>
>print "Got input! Verifying..."
>
>print inputnum
>```

Let's try this with 2 different orders:

What order?
2
Input numbers.
1
2
3
4
5
6
7
Got input! Verifying...
[[1, 2], [3, 4, 5], [0, 6, 7, 0]]

and 

What order?
3
Input numbers.
1
2
3
4
5
6
7
8
9
0
1
2
3
4
5
6
7
8
9
Got input! Verifying...
[[1, 2, 3], [4, 5, 6, 7], [8, 9, 0, 1, 2], [0, 3, 4, 5, 6, 0], [0, 0, 7, 8, 9, 0, 0]]

As we can see, the program creates a sort of cut-off matrix in which the values get stored, with the final rows padded on left and right sides. We'll come back to this later.
What we need to know next is how crypto1 decides if our input is valid:

>```c
>__int64 __fastcall crypto1(__int64 input, int order)
>{
>  __int64 result; // rax@4
>  void *buf; // [sp+18h] [bp-78h]@1
>  int i; // [sp+20h] [bp-70h]@1
>  int j; // [sp+24h] [bp-6Ch]@2
>  int v6; // [sp+28h] [bp-68h]@13
>  int k; // [sp+2Ch] [bp-64h]@13
>  int v8; // [sp+30h] [bp-60h]@20
>  int l; // [sp+34h] [bp-5Ch]@20
>  int m; // [sp+38h] [bp-58h]@23
>  int v11; // [sp+3Ch] [bp-54h]@24
>  int n; // [sp+40h] [bp-50h]@24
>  int ii; // [sp+44h] [bp-4Ch]@31
>  int v14; // [sp+48h] [bp-48h]@32
>  int jj; // [sp+4Ch] [bp-44h]@32
>  int kk; // [sp+50h] [bp-40h]@39
>  int v17; // [sp+54h] [bp-3Ch]@40
>  int ll; // [sp+58h] [bp-38h]@40
>  int mm; // [sp+5Ch] [bp-34h]@47
>  int v20; // [sp+60h] [bp-30h]@48
>  int nn; // [sp+64h] [bp-2Ch]@48
>  int i1; // [sp+68h] [bp-28h]@55
>  int v23; // [sp+6Ch] [bp-24h]@56
>  int i2; // [sp+70h] [bp-20h]@56
>  int idword; // [sp+74h] [bp-1Ch]@3
>
>  buf = calloc(3 * order * order + -3 * order + 1, 4uLL);
>  for ( i = 0; 2 * order - 1 > i; ++i )
>  {
>    for ( j = 0; order + i > j; ++j )
>    {
>      idword = *(_DWORD *)(4LL * j + *(_QWORD *)(input + 8LL * i));
>      if ( 3 * order * order + -3 * order + 1 < idword )
>        return 0LL;
>      if ( idword < 0 )
>        return 0LL;
>      if ( idword > 0 )
>        ++*((_DWORD *)buf + idword - 1LL);
>    }
>  }
>  v6 = 0;
>  for ( k = 0; 3 * order * order + -3 * order + 1 > k; ++k )
>  {
>    v6 += *((_DWORD *)buf + k);
>    if ( *((_DWORD *)buf + k) > 1 )
>      return 0LL;
>  }
>  if ( 3 * order * order + -3 * order + 1 == v6 )
>  {
>    v8 = 0;
>    for ( l = 0; l < order; ++l )
>      v8 += *(_DWORD *)(4LL * l + *(_QWORD *)input);
>    for ( m = 0; 2 * order - 1 > m; ++m )
>    {
>      v11 = 0;
>      for ( n = 0; order + m > n; ++n )
>        v11 += *(_DWORD *)(4LL * n + *(_QWORD *)(input + 8LL * m));
>      if ( v11 != v8 )
>        return 0LL;
>    }
>    for ( ii = 0; ii < order; ++ii )
>    {
>      v14 = 0;
>      for ( jj = 0; order + ii > jj; ++jj )
>        v14 += *(_DWORD *)(4LL * ii + *(_QWORD *)(input + 8LL * jj));
>      if ( v14 != v8 )
>        return 0LL;
>    }
>    for ( kk = order; 2 * order - 1 > kk; ++kk )
>    {
>      v17 = 0;
>      for ( ll = 0; ll < 2 * order - 1 + ~(kk - order); ++ll )
>        v17 += *(_DWORD *)(4LL * kk + *(_QWORD *)(input + 8LL * (ll + kk - order + 1)));
>      if ( v17 != v8 )
>        return 0LL;
>    }
>    for ( mm = 0; mm < order; ++mm )
>    {
>      v20 = 0;
>      for ( nn = 0; 2 * order - 1 - mm > nn; ++nn )
>        v20 += *(_DWORD *)(4LL * nn + *(_QWORD *)(input + 8LL * (mm + nn)));
>      if ( v20 != v8 )
>        return 0LL;
>    }
>    for ( i1 = 1; i1 < order; ++i1 )
>    {
>      v23 = 0;
>      for ( i2 = 0; 2 * order - 1 - i1 > i2; ++i2 )
>        v23 += *(_DWORD *)(4LL * (i1 + i2) + *(_QWORD *)(input + 8LL * i2));
>      if ( v23 != v8 )
>        return 0LL;
>    }
>    if ( **(_DWORD **)input + **(_DWORD **)(input + 8) == 20 )
>      result = **(_DWORD **)input == 9;
>    else
>      result = 0LL;
>  }
>  else
>  {
>    result = 0LL;
>  }
>  return result;
>}
>```

While it's not obvious right away the above code determines the sum of the first row and checks whether all rows, columns and 3 diagonals all sum to this value. It also checks whether the first elements of the first and second rows sum to 20 and whether the first element of the first row is 9.

It turns out this is a [magic hexagon](http://en.wikipedia.org/wiki/Magic_hexagon) but we mistook it for a magic square with relaxed constraints (zeros in several cells) so we decided to model the magic square problem as a constraint-based programming problem in order to solve a system of linear equations. We simply assign a variable to each cell, with the variables of a and f (first row, first cell & second row, first cell) set to 9 and 11 (sum to 20). We determine the 'magic number' sum in a brute-force fashion by iterating over all possible values of k (since a+k+f = sum of first column) and put constraints on the row, column and diagonal sums to equal the magic number. We don't know the initial order but given that the minimum order is 2 and no system of linear equations produced by order 2 can be a valid solution (as one of the diagonals sums to 0) we decide to start at 3 and see from there. Using [python-constraint](https://labix.org/python-constraint) we end up with the following keygen:

>```python
>#!/usr/bin/python
>#
># Plaid CTF 2015
># Clifford (REVERSING/100)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from constraint import *
>import string
>
>def bfsize(order):
>    return (3 * order * order + -3 * order + 1)
>
>def solve(order, k_val):
>    # Set of possible values for cells
>    charset = range(0, bfsize(order)+1)
>    # Magic number sum
>    magic_number = 20 + k_val
>    # Already chosen
>    picked = [9, 11, k_val]
>    # Not yet chosen
>    free_charset = [x for x in charset if not(x in picked)]
>    # All cell names
>    all_variables = string.lowercase[:len(string.lowercase)-1]
>    # Free variables
>    free_variables = all_variables.replace('a','').replace('f', '').replace('k', '')
>    # Variables for which the uniqueness constraint holds
>    diff_variables = [x for x in all_variables if not(x in ['d','e','j','p','u','v'])]
>
>    problem = Problem()
>    # Pre-set variables
>    problem.addVariable('a', charset)
>    problem.addVariable('k', charset)
>    problem.addVariable('f', charset)
>    # Free variables
>    problem.addVariables(free_variables, free_charset)
>
>    # Base constraints
>    problem.addConstraint(lambda field: field==9, ['a'])
>    problem.addConstraint(lambda field: field==0, ['d'])
>    problem.addConstraint(lambda field: field==0, ['e'])
>    problem.addConstraint(lambda field: field==11, ['f']) # 11 = 20 - 9
>    problem.addConstraint(lambda field: field==0, ['j'])
>    problem.addConstraint(lambda field: field==k_val, ['k'])
>    problem.addConstraint(lambda field: field==0, ['p'])
>    problem.addConstraint(lambda field: field==0, ['u'])
>    problem.addConstraint(lambda field: field==0, ['v'])
>
>    # Uniqueness constraint
>    problem.addConstraint(AllDifferentConstraint(), diff_variables)
>
>    # Rows & Columns
>
>    block_size = 5
>    rows = [all_variables[i:i+block_size] for i in range(0, len(all_variables), block_size)]
>    columns = []
>    for i in xrange(block_size):
>        column = ""
>        for j in xrange(len(rows)):
>            column += rows[j][i]
>        columns.append(column)
>
>    # Row, column & diagonal sum constraints
>
>    for i in xrange(len(rows)):
>        problem.addConstraint(ExactSumConstraint(magic_number), rows[i])
>
>    for i in xrange(len(columns)):
>        problem.addConstraint(ExactSumConstraint(magic_number), columns[i])
>
>    problem.addConstraint(ExactSumConstraint(magic_number), 'agmsy')
>    problem.addConstraint(ExactSumConstraint(magic_number), 'flrx')
>    problem.addConstraint(ExactSumConstraint(magic_number), 'kqw')
>
>    solution = problem.getSolution()
>    if (solution):
>        print "[+]Solution: "
>        print solution
>        return True
>    else:
>        return False
>
>order = 3
>for i in xrange(0, bfsize(order)+1):
>    if(i == 9):
>        continue
>
>    print "[*]Trying k=%d" % i
>
>    if(solve(order, i)):
>        exit()
>
>print "[-]Got nothing :("
>```

Which produces the following output:

>```bash
>$ python clifford_keygen.py
>[*]Trying k=0
>[*]Trying k=1
>[*]Trying k=2
>[*]Trying k=3
>(...)
>[*]Trying k=18
[+]Solution:
{'a': 9, 'c': 15, 'b': 14, 'e': 0, 'd': 0, 'g': 6, 'f': 11, 'i': 13, 'h': 8, 'k': 18, 'j': 0, 'm': 5, 'l': 1, 'o': 10, 'n': 4, 'q': 17, 'p': 0, 's': 2, 'r': 7,
'u': 0, 't': 12, 'w': 3, 'v': 0, 'y': 16, 'x': 19}
>```

Inputting those values into the binary gives us:

>```bash
>$ ./clifford 
>What order?
>3
>Input numbers.
>9
>14
>15
>11
>6
>8
>13
>18
>1
>5
>4
>10
>17
>7
>2
>12
>3
>19
>16
>Got input! Verifying...
>Success!
>Your flag is: too_bad_this_took_20_years_to_find!!
>```