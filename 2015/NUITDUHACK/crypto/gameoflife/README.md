# Nuit Du Hack CTF 2015: Game Of Life

**Category:** Crypto
**Points:** 150
**Description:** 

>"We're born alone, we live alone, we die alone. Only through our love and friendship can we create the illusion for the moment that we're not alone." (Orson Orwell)
>
>[Cells cells cells, the basis of life](challenge/GOL.tar.gz). Don't let them die and tell us their secret.

## Write-up

The challenge archive contains 3 files.

consignes:

> [ Game of life ]
> 
> [+] The above text has been encoded using the game of life rules on a 8x8 array.

cipher.txt:

>11000100
>
>00010000
>
>01000111
>
>(...)
>
>YDUC
>
>(...)

And a python file jdlv.py which allows you to encrypt your input with the cipher used to encrypt cipher.txt. Let's take a look its core functions:

>```python
>def wrapper():
>    key=sys.argv[1]
>    fichier=open(sys.argv[2],'rb')
>    encfile=''
>    bitstream=''
>    grille=initGrille(creerGrille(),genKey(key))
>    for i in fichier.readlines():
>        bitstream=genBitstream(grille,key)
>        encfile+=xor(i,bitstream)
>        tourSuivant(grille)
>    print encfile
>```

The wrapper function creates a 8x8 matrix which it initializes using the result of genKey over the supplied master key. It subsequently reads the plaintext line-by-line, generates a bitstream using genBitstream and xors the lines with the bitstream before calling tourSuivant. Let's take a closer look at some of these helper functions first:

>```python
>def genKey(key):
>    psk=hashlib.sha256(key)
>    buff=""
>    seed=""
>    for char in psk.hexdigest():
>        buff+=bin(ord(char))[2:]
>    for c in buff:
>        seed+=c
>    return seed
>```

As we can see genKey creates a master key out of the supplied password by taking the binary representation of the hex representation of the SHA256 hash of the supplied password. This means that the resulting key will always be 256 characters long and consist only of the characters '0' and '1'.

>```python
>def initGrille(grille,seed):
>    for (i, j), c in itertools.izip(itertools.product(xrange(len(grille)), reversed(xrange(len(grille[0])))), seed):
>        grille[i][j] = c
>    return grille
>```

The function initGrille initializes a grid from a seed in the following fashion:

> (0, 7)  seed[0]
>
> (0, 6)  seed[1]
>
> (0, 5)  seed[2]
>
> ...

The function xor does exactly what it says on the tin and implements a repeating-key xor function:

>```python
>def xor(ent1,ent2):
>    key=itertools.cycle(ent2)
>    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in itertools.izip(ent1, key))
>```

The function genBitstream creates an stream consisting of the concatenation of the 8th column of all the 8 rows of the supplied grid (hence, the bitstream will always be 8 bytes long and consist only of the characters '0' and '1'):

>```python
>def genBitstream(grille,key):
>    bitstream=''
>    for j in range(8):
>        bitstream+=grille[j][7]
>    return bitstream
>```

Finally this leaves us with the function tourSuivant which simply implements the rules of [Conway's Game Of Life](http://en.wikipedia.org/wiki/Conway%27s_Game_of_Life) over a given grid:

>```python
>def tourSuivant(grille):
>    tabbuff=[[0]*8 for _ in range(8)]
>    for j in range(8):
>        for i in range(8):
>            voisine=0
>            if grille[(j-1%8)][(i-1)%8] != '0':
>                voisine+=1
>            if grille[(j-1)%8][i] != '0':
>                voisine+=1
>            if grille[(j-1)%8][(i+1)%8] != '0':
>                voisine+=1
>            if grille[j][(i-1)%8] != '0':
>                voisine+=1
>            if grille[j][(i+1)%8] != '0':
>                voisine+=1
>            if grille[(j+1)%8][(i-1)%8] != '0':
>                voisine+=1
>            if grille[(j+1)%8][i] != '0':
>                voisine+=1
>            if grille[(j+1)%8][(i+1)%8] != '0':
>                voisine+=1
>            tabbuff[j][i]=voisine
>        
>    for j in range(8):
>        for i in range(8):
>            if tabbuff[j][i]==3 and grille[j][i]== '0':
>                grille[j][i]='1'
>            elif tabbuff[j][i] < 2 or tabbuff[j][i] > 3:
>                grille[j][i]='0'
>    return grille
>```

This means we're effectively dealing with a streamcipher where the initial keystate (in the form of the initial grid derived from the supplied password) is permutated through the use of the rules of the Game Of Life as a PRNG, switching to a new keystate for every line of plaintext. Each line of plaintext is then encrypted using a repeating-key xor operation with a key derived from the current keystate.

There are multiple problems here, from the use of a repeating-key xor operation to the simple use of the rules of the Game Of Life as a relatively invertable (and potentially deadlocking) PRNG and the fact that the keystate is limited to a characterset of only 2 characters. Given that plaintext data is encrypted using a repeating-key xor operation and the keystate (and hence the bitstream) always consists of only the characters '0' and '1' we know that whenever the ciphertext contains the characters '0' or '1' we are dealing with the following scenarios:

> If the ciphertext character is '0' (0x30) either:
> 	- plaintext = 0x00, key = '0' (0x30)
> 	- plaintext = 0x01, key = '1' (0x31)

> If the ciphertext character is '1' (0x31) either:
> 	- plaintext = 0x00, key = '1' (0x31)
> 	- plaintext = 0x01, key = '0' (0x30)

If we look at the ciphertext in cipher.txt we see a series of 114 lines (all of length 8) consisting of only '0' and '1':

> 11000100
>
> 00010000
>
> 01000111
>
> (...)
>
> 00000000
>
> 00000000
>
> 00000000

Let's assume these lines are the result of 8-byte blocks of null-bytes followed by a 0x0A byte (interpreted as a newline seperator) then the first 114 lines of the ciphertext are an effective dump of the bitstreams (and hence the partial keystates they correspond with). Seeing as how the lines eventually all become "00000000" it is safe to assume that the Game Of Life PRNG, during encryption, had reached a deadlock state where no change will occur anymore and hence all subsequent bitstreams beyond that point will be the same (seeing as how the keystate will remain the same). This means we can assume all subsequent data is encrypted with the same, dumped, bitstream "00000000" which allows us to trivially decrypt the ciphertext using the [following little script](solution/gameoflifesolution.py):

>```python
>#!/usr/bin/python
>#
># Nuit Du Hack CTF 2015
># Game Of Life (CRYPTO/150) Solution
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import itertools
>
>def xor(ent1, ent2):
>    key = itertools.cycle(ent2)
>    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in itertools.izip(ent1, key))
>
>f = open("cipher.txt", 'rb')
>lines = f.readlines()
>
>encfile = ''
>for i in xrange(114, len(lines)):
>	bitstream = '00000000'
>	data = lines[i][0: len(lines[i])-1]
>	encfile += xor(data, bitstream)
>
>print encfile
>```

Which produces the following output:

>```bash
>$ python gameoflifesolution.py
>!!   !  !!   !  !!   !  Md maoifdrte eu usacetr
>Autdur  lolbredudr`gon
>Zhne ;!Sagale!"2
>
>(Tsacetr =!prauiqu`nt eu P`rkotr)
>(...)
>Flag  ToBeAndToLast
>```