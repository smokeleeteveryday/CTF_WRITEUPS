# VolgaCTF Quals 2015: Rsa

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| VolgaCTF Quals 2015 | Rsa | Crypto |    200 |

**Description:**
>*rsa*

>*The oldie but goodie.*

>*[script](challenge/decryptor.py)*

>*[key](challenge/key.public)*

>*[ciphertext](challenge/ciphertext.bin)*

----------
## Write-up
### First look

We start out by looking at the RSA public key provided

>```
>[+]n: [0x323fada9cfa3c3037e0b907d2cea83b9ad3655092cb04aeed95500bca4e366a06cb4d215c65bb3d630b779d27bdc8dcd907d655acbdcef465e411beb1be3dddaaba20fb058e7850aa355ec1b89358602fde7f8be59d4150770cacc1b77b775f7caa358167b3226515f15fca8a4659fea2c4efb0360e31993dde4d1c199832b89L] (1022 bits)
>
>[+]e: [0x1e4805a218009c7f779033e3378b07693f56b266786a295b32d7275ae2e2cd3449dac7468cdae9bb04f547ec759e560739e0d448ebba0ded244095fe1d9b900a885ae931ec760715dbdee4acddb6170b036753c8b572c8af9a02ef370d41a0f2009388bfa042b9f1d0d0847e2fd6fd7ac9e231b17cc95d1dec4540681262c919L] (1021 bits)
>```

As we can see, we are dealing with a very large public exponent. While this isn't necessarily always the case, this can be an indication of a corresponding small RSA private exponent. In a lot of (but [not all](https://www.cryptologie.net/article/265/small-rsa-private-key-problem/)) cases using [Wiener's attack](http://en.wikipedia.org/wiki/Wiener%27s_attack) will suffice to recover the private exponent.

### Attack

Running the [following code](solution/rsa_crack.py):

>```python
>#!/usr/bin/python
>#
># VolgaCTF Quals 2015
># Rsa (Crypto/200)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import math
>from Crypto.PublicKey import RSA
>
>def number_of_bits(n):
>  return int(math.log(n, 2)) + 1
>
>def isqrt(n):
>  if n < 0:
>      raise ValueError('[-]Square root not defined for negative numbers')    
>  if n == 0:
>      return 0
>
>  a, b = divmod(number_of_bits(n), 2)
>  x = 2**(a+b)
>
>  while True:
>      y = (x + n//x)//2
>      if y >= x:
>          return x
>      x = y
>
>def perfectSquare(n):
>  h = n & 0xF    
>  if h > 9:
>      return -1
>
>  if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
>      t = isqrt(n)
>      if (t*t == n):
>          return t
>      else:
>          return -1    
>  return -1
>
># Fraction p/q as continued fraction
>def contfrac(p, q):
>  while q:
>      n = p // q
>      yield n
>      q, p = p - q*n, q
>
># Convergents from continued fraction
>def convergents(cf):
>  p, q, r, s = 1, 0, 0, 1
>  for c in cf:
>      p, q, r, s = c*p+r, c*q+s, p, q
>      yield p, q
>
># Wiener's attack ported from https://github.com/pablocelayes/rsa-wiener-attack
>def wienerAttack(n, e):
>  cts = convergents(contfrac(e, n))    
>  for (k, d) in cts:   
>      # check if d is actually the key
>      if ((k != 0) and ((e*d - 1) % k == 0)):
>          phi = ((e*d - 1)//k)
>          s = n - phi + 1
>          # check if the equation x^2 - s*x + n = 0
>          # has integer roots
>          discr = s*s - 4*n
>          if(discr >= 0):
>              t = perfectSquare(discr)
>              if ((t != -1) and ((s+t) % 2 == 0)):
>                  return d
>  return None
>
>f = open("key.public", 'rb')
>externKey = f.read()
>f.close()
>
>pubkey = RSA.importKey(externKey)
>d = wienerAttack(pubkey.n, pubkey.e)
>if(d):
>	print "[+]Recovered d: [%d]!" % d
>	privkey = RSA.construct((pubkey.n, pubkey.e, d, ))
>	with open('ciphertext.bin', 'rb') as f:
>		C = f.read()
>	print "[+]Flag: [%s]" % privkey.decrypt(C)
>```

Gives us the following output:

>```bash
>$ ./rsa_crack.py
>[+]Recovered d: [3742521278975183332886178478932181208106789375560965837781]!
>
>[+]Flag: [{shorter_d_is_quicker_but_insecure}]
>```