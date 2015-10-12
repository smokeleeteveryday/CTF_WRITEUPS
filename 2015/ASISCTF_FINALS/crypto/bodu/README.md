# ASISCTF Finals 2015: Bodu

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASISCTF Finals 2015 | Bodu | Crypto |    175 |

**Description:**
>*Find the flag in [this](challenge/pub.key) [file](challenge/flag.enc).*

----------
## Write-up

We're given an RSA public key:

```
-----BEGIN PUBLIC KEY-----
MIIBHjANBgkqhkiG9w0BAQEFAAOCAQsAMIIBBgKBgAOmFghI+xc0y9D6Is71guhJ
IjrARRDVFQJVa2R20HOX8D3xVSicIBEuh8bzU2HZ62IspKDlLZzYe/cjUmyCa4g4
fQarxCeeNT8SrY7GLqc8RzIaILiWRIiaeSpzFSvHAUuAppPS5YsSP6klw1ax66A3
pNysjY3oCRZ6b8wwxceFAoGAA2WWLo2rp7qS/Ah2il9zs4VPTHmWnVUYoHigNEN8
Rmm9twW+TYuLq/T9oabnFSaeh7KO7LDU4Ccmon+4chhjdAcg9YNojlVn6xBym7DZ
KzItcZlJ5AxXGY12TxxjPl4nfaPTKB7OLOLrTflFvlr8PnhJjtBImyRZBZZk/hXI
ijM=
-----END PUBLIC KEY-----
```

And a flag ciphertext:

```
0x025051c6c4e82266e0b9e8a47266531a01d484b0dc7ee629fb5a0588f15bf50281f46cf08be71e067ac7166580f144a6bdcc83a90206681c2409404e92474b37de67d92fd2fa4bc4bd119372b6d50c0377758fc8e946d203a040e04d6bfe41dfb898cd4e36e582f16ad475915ac2c6586d874dd397e7ed1cb2d3f2003586c257
```

Inspecting the RSA public key gives us the public modulus en exponent:

```
n = 2562256018798982275495595589518163432372017502243601864658538274705537914483947807120783733766118553254101235396521540936164219440561532997119915510314638089613615679231310858594698461124636943528101265406967445593951653796041336078776455339658353436309933716631455967769429086442266084993673779546522240901

e = 2385330119331689083455211591182934261439999376616463648565178544704114285540523381214630503109888606012730471130911882799269407391377516911847608047728411508873523338260985637241587680601172666919944195740711767256695758337633401530723721692604012809476068197687643054238649174648923555374972384090471828019
```

The very large public exponent immediately leads us to suspect an attack on a small private exponent (like the instance of [Wiener's Attack](https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/PCTF/crypto/curious) in this year's PlaidCTF). A quick evaluation of Wiener's attack yielded no such luck however but we recalled that [Boneh and Durfee](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.258.8220&rep=rep1&type=pdf) extended the bound for low private exponents from Wiener's 0.25 bound (meaning the private exponent d is bounded by c*N^0.25) to 0.292 allowing for recovery of bigger (small) private exponents. The attack and the background (the usage of lattice reduction techniques such as the LLL algorithm, Coppersmith's attack on a relaxed RSA model and subsequent improvements by Boneh and Durfee and Herrman and May) are explained very well by David Wong [here](https://github.com/mimoo/RSA-and-LLL-attacks/) and [here](https://www.cryptologie.net/article/265/small-rsa-private-key-problem/). Wong, who mentioned our solution (and its limits) of using Wiener's attack for the `curious` challenge of this year's PlaidCTF also provides a nice [sage worksheet](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage) which we could plug our public key into to obtain the private exponent `d = 89508186630638564513494386415865407147609702392949250864642625401059935751367507` which we could then use to decrypt the ciphertext yielding the flag: `ASIS{b472266d4dd916a23a7b0deb5bc5e63f}`