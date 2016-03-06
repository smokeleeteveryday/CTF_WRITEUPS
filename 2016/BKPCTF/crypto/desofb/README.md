# BKPCTF 2016: des-ofb

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| BKPCTF | des-ofb | Crypto | 2 |

### Description
> Decrypt the message, find the flag, and then marvel at how broken everything is. [https://s3.amazonaws.com/bostonkeyparty/2016/e0289aac2e337e21bcf0a0048e138d933b929a8c.tar](challenge)

## Write-up

This challenge consists of a small python script and a ciphertext file. The script looks as follows:

```python
from Crypto.Cipher import DES

f = open('key.txt', 'r')
key_hex = f.readline()[:-1] # discard newline
f.close()
KEY = key_hex.decode("hex")
IV = '13245678'
a = DES.new(KEY, DES.MODE_OFB, IV)

f = open('plaintext', 'r')
plaintext = f.read()
f.close()

ciphertext = a.encrypt(plaintext)
f = open('ciphertext', 'w')
f.write(ciphertext)
f.close()
```

Its a trivial application of the DES block cipher in the [OFB mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29) using an unknown key and IV `13245678`. If we look at a diagram of the OFB mode of operation we can see it is a streaming mode of operation which effectively turns a block cipher into a stream cipher via generation of a continuous keystream derived from iterative application of the block encryption function to the IV.

![alt ofb](ofb.png)

When dealing with streamciphers one has to be careful to avoid keystream repetition (eg. through IV reuse, short PRNG periods, etc.). In this case in particular consequences are dire if DES is used with a so-called ['weak key'](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES) where E(E(P, K), K) = P thus meaning every even block of keystream is identical to the (publicly known) IV and every odd block of keystream is identical to E(IV, K). We can use this to disclose the even blocks of plaintext and attempt derivation of the odd keystream block using a known plaintext attack in order to disclose the entire plaintext [as follows](solution/desofb_crack.py):

```python
import string
from Crypto.Cipher import DES

def is_printable(s):
    return all(c in (string.printable) for c in s)

def get_blocks(data, block_size):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

c = open("ciphertext", "rb").read()
IV = '13245678'
bs = DES.block_size

assert (len(c) % bs == 0), "[-] Ciphertext not a multiple of DES blocksize"

blocks = get_blocks(c, bs)

for b in blocks:
    x = xor_strings(b, IV)
    if (is_printable(x)):
        print x
```

The result is clearly part of the ['To be or not to be'](https://en.wikipedia.org/wiki/To_be,_or_not_to_be) soliloquy of Shakespeare's Hamlet:

```
r not to
t is the
n:
Wheth
Nobler i
nd to su
 Slings
ws of ou
 Fortune
take Arm
t a Sea
les,
And
sing end
o die, t
No more;
```

We can use the rest of the text to derive the first 8 keystream bytes via known plaintext and thus reconstruct the full plaintext:

```python
p = " be, tha"
k = xor_strings(blocks[2], p)

s = ""
for i in xrange(len(blocks)):
    if (i % 2 == 0):
        b = xor_strings(blocks[i], k)
    else:
        b = xor_strings(blocks[i], IV)

    s += b

print s
```

Which gives us:

```
...
Is sicklied o'er, with the pale cast of Thought,
And enterprises of great pitch and moment,
With this regard their Currents turn awry,
And lose the name of Action. Soft you now,
The fair Ophelia? Nymph, in thy Orisons
Be all my sins remembered. BKPCTF{so_its_just_a_short_repeating_otp!}
```