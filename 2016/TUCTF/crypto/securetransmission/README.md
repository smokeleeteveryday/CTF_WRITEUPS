# TU CTF 2016: secure transmission

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| TU CTF | secure transmission | Crypto | 150 |

### Description
> We were able to recover this network traffic from some shady giraffes... Can you tell what they were saying?
>
>#note this flag is in the form: flag{...}

## Write-up

We are given a [PCAP with intercepted traffic](challenge/40bec2fdb682af3046465a54f7776c8adb26ea4d.pcapng) holding two conversations, one being the downloading of a [compiled python script](challenge/client.pyc) over HTTP and the other being traffic to a custom 'secure' communication service. If we decompile the compiled python client script we get the following code:

```python
import socket
from Crypto import Random
rand = Random.new()
from Crypto.Cipher import AES
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.188.129', 54321))
welcome = s.recv(1024).strip('\n')
print welcome
g = s.recv(1024).strip('\n').split('g:')[1]
print g
p = s.recv(1024).strip('\n').split('p:')[1]
print p
A = s.recv(1024).strip('\n').split('A:')[1]
print A
prompt = s.recv(1024).strip('\n')
print prompt
A = int(A)
g = int(g)
p = int(p)
b = int(rand.read(8).encode('hex'), 16)
B = pow(g, b, p)
s.send(str(B))
my_key = pow(A, b, p)
print 'secret key: {}'.format(my_key)
msg = s.recv(1024).strip('\n')
print '********************'
print 'encrypted message:'
print msg.encode('hex')
print ''
plain = ''
for i in msg.split('\n'):
    if not i.startswith('Good data!'):
        aes_key = hex(my_key).strip('0x').strip('L')
        while len(aes_key) < 32:
            aes_key = '0' + aes_key

        obj = AES.new(aes_key.decode('hex'), AES.MODE_CBC, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        plain += obj.decrypt(i)

print plain
```

We can see that a (Diffie-Hellman Key Exchange)[https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange] takes place and an AES key is derived from the established shared secret. The AES key is then used to decrypt a received ciphertext message (holding the flag) using AES in CBC mode with a static (all NULL) IV.

Taking a look at the intercepted convo we see the following:

```
Welcome to the awsome DH exchange!
g:429072158523821662
p:594830787528835483
A:313868463457946531
What is your B?
123114413580763739Good data!
    ......J..8T$L.CZm...... ...J..D
```

We know group generator `g`, order `p`, Alice's public value `A = g^a mod p` and Bob's public value `B = g^b mod p`. The shared secret we are after is `A^b mod p = B^a mod p = (g^a)^b mod p = (g^b)^a mod p = g^(ab) mod p`. The security of DHKE lies in the fact that for an outside observer determining `a` or `b` given `A` or `B` comes down to the [Discrete Logarithm Problem](https://en.wikipedia.org/wiki/Discrete_logarithm) in a suitable (and suitably large) group. In this case, however, we are dealing with a small group where the problem is solved in reasonable time by the following SageMath script:

```python
p = 594830787528835483
R = Integers(p)
B = R(123114413580763739)
g = R(429072158523821662)
b = B.log(g)

print b

A = 313868463457946531
my_key = pow(A, b, p)
aes_key = hex(my_key).strip('0x').strip('L')
while len(aes_key) < 32:
    aes_key = '0' + aes_key
```

Using the above script (where `b = 747027`) and the resulting aes_key we can decrypt the intercepted ciphertext (`09f5d9d2c41db04aee983854244cc3435a6daa90d3e186b509c3ac9d4a94dc44`) yielding the flag `flag{breaking_dh_like_the_nsa!}`