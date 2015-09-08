# MMACTF 2015: simple_hash

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| MMACTF 2015 | simple_hash | Reversing |    200 |

**Description:**
>*[Get the flag!](challenge/simple_hash)
>
>nc milkyway.chal.mmactf.link 6669*

----------
## Write-up

We're presented with a 32-bit ELF binary for which IDA gives the following pseudocode:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  bool correct_flag; // al@5
  FILE *v4; // ST1C_4@8

  fgets(&input, 999, stdin);
  if ( input )
    *(&input + strlen(&input) - 1) = 0;
  correct_flag = (unsigned __int8)isvalid() && calc_hash() == 0x1E1EAB437EEB0LL;
  if ( correct_flag )
  {
    puts("Correct!");
    v4 = fopen("./flag.txt", "r");
    fgets(&input, 999, v4);
    fclose(v4);
    printf("\n%s", &input);
  }
  else
  {
    puts("Wrong!");
  }
  return 0;
}

signed int isvalid(void)
{
  int i; // [sp+1Ch] [bp-Ch]@1

  for ( i = 0; *(_BYTE *)(i + 0x80491A0); ++i )
  {
    if ( !isalnum(*(_BYTE *)(i + 0x80491A0)) )
      return 0;
  }
  return 1;
}

signed __int64 calc_hash(void)
{
  int i; // [sp+14h] [bp-14h]@1
  __int64 v2; // [sp+18h] [bp-10h]@1

  v2 = 0LL;
  for ( i = 0; *(_BYTE *)(i + 0x80491A0); ++i )
    v2 = (mm(v2, 577LL) + *(_BYTE *)(i + 0x80491A0)) % 1000000000000037LL;
  return v2;
}

__int64 __cdecl mm(__int64 a1, __int64 a2)
{
  __int64 result; // rax@2
  __int64 v3; // rax@3
  __int64 v4; // [sp+48h] [bp-10h]@3

  if ( a2 )
  {
    LODWORD(v3) = mm(2 * a1 % 0x38D7EA4C68025LL, a2 / 2);
    v4 = v3;
    if ( __PAIR__(
           (unsigned __int64)(SHIDWORD(a2) >> 31) >> 32,
           (SHIDWORD(a2) >> 31) ^ (((unsigned __int8)(SHIDWORD(a2) >> 31) ^ (unsigned __int8)a2)
                                 - (unsigned __int8)(SHIDWORD(a2) >> 31)) & 1u)
       - (SHIDWORD(a2) >> 31) == 1 )
      v4 = (v3 + a1) % 0x38D7EA4C68025LL;
    result = v4;
  }
  else
  {
    result = 0LL;
  }
  return result;
}
```

As we can see we are dealing with a hash of some kind and have to find a corresponding preimage (that is, a value m such that H(m) = 0x1E1EAB437EEB0) to the embedded hash value. In addition there is a check on the input to see if it is alphanumeric. Reversing the above functions eventually allows us to reduce the hash function to the following recursive function:

```python
def hashf(inp):
	state = 0
	for c in inp:
		state = ((state * 0x241) + ord(c)) % 0x38D7EA4C68025
	return state
```

What we're dealing with here is a [multiplicative](http://www.cs.cornell.edu/courses/cs3110/2008fa/lectures/lec21.html) [hash function](http://www.strchr.com/hash_functions) with the following parameters:

```
initial_state = 0
multiplier = 0x241
modulus = 0x38D7EA4C68025
```

As per good practice both the multiplier and modulus are prime numbers but while multiplicative hash functions might be relatively fast but they are not cryptographically secure and usually quite prone to collisions. In addition the large modulus will only start 'wrapping' the internal state around from inputs of 6 or more characters meaning any input shorter than that can be directly recovered in the following iterative fashion:

```python
def recover_m(h):
	s = ""
	while (h > 0):
		c = (h % 0x241)
		s += chr(c)
		h -= c
		h /= 0x241
	return s[::-1]
```

Alas, this is not the case for our input which does indicate it consists of 6 characters or more.

What we can do, however, is use the fact that the hash function increases linearly (within modular bounds) corresponding to the input ASCII values, eg.: hashf("AB") = (hashf("AA") + 1) mod 0x38D7EA4C68025. Hence we can initialize an input *m* to the lowest cumulative ASCII value for that string length (ie. all "0" characters) and for each position incrementally test whether a given candidate character at that position could be eligible. That is, if the target hash lies between the hash value of a candidate string with character *x* at position *i* and that of candidate string with character *(x+1)* at position *i* then character *x* is a candidate character for that position. For each position we obtain such a set of candidates and recursively apply this process to all possible candidate strings for subsequent positions until we find the correct hash value. This process can be repeated for different candidate string lengths ranging from our established minimum of 6 to 12 (which we considered a reasonable upper bound). This gives [the following script](solution/simple_hash_crack.py):

```python
#!/usr/bin/env python
#
# MMACTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import string

# Alphanumeric alphabet (ordered by ASCII value)
charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Recursive version of hash function (as reversed)
def hashf(inp):
	# Multiplier
	M = 0x241
	# Modulus
	P = 0x38D7EA4C68025
	# Initial state
	state = 0
	for c in inp:
		state = ((state * M) + ord(c)) % P
	return state

# Fetches candidate characters for a given position
def index_candidate_chars(target, candidate, index):
	global charset

	r = []

	# Start out with lowest ASCII value
	tmp_candidate = list(candidate)
	tmp_candidate[index] = charset[0]
	tmp_candidate = "".join(tmp_candidate)
	p_hash = hashf(tmp_candidate)

	# Work through entire character set
	for j in xrange(1, len(charset)):
		tmp_candidate = list(tmp_candidate)
		tmp_candidate[index] = charset[j]
		tmp_candidate = "".join(tmp_candidate)
		n_hash = hashf(tmp_candidate)
		
		# Have we found it?
		if(n_hash == target):
			print "[+]Cracked input: [%s] (0x%x)" % (tmp_candidate, n_hash)
			exit()

		# If the target is in between the previous and current hash value we consider the previous character a candidate for this position
		if ((p_hash < target) and (target < n_hash)):
			r.append(charset[j-1])

		p_hash = n_hash

	return r + [charset[len(charset)-1]]

# Recursive cracking function
def crack(target, candidate, index):
	global charset

	if (index >= len(candidate)):
		return

	chars = index_candidate_chars(target, candidate, index)

	# Branch out over all candidate characters at this position
	for c in chars:
		tmp_candidate = list(candidate)
		tmp_candidate[index] = c
		tmp_candidate = "".join(tmp_candidate)
		crack(target, tmp_candidate, index + 1)

	return

# Target hash
h = 0x1E1EAB437EEB0

# Try different lengths
min_len = 6
max_len = 12

for i in xrange(min_len, max_len+1):
	print "[*]Trying length %d..." % i
	# Initial candidate (lowest cumulative value)
	candidate = charset[0]*i
	crack(h, candidate, 0)
```

which when run gives the answer within reasonable time:

```bash
$ ./simple_hash_crack.py
[*]Trying length 6...
[*]Trying length 7...
[*]Trying length 8...
[*]Trying length 9...
[*]Trying length 10...
[+]Cracked input: [5iyP7znv7R] (0x1e1eab437eeb0)

$ nc milkyway.chal.mmactf.link 6669
5iyP7znv7R
Correct!

MMA{mocho is cute}
```