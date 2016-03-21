# BCTF 2016: zerodaystore

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| BCTF | zerodaystore | Misc. | 200 |

### Description
> [server.py.8c15b34d5e32243f5ed38c1b055bfd6f](challenge)
>
> [zerodaystore.apk.7869c5b00cdf037273e39572fb1affdb](challenge)

## Write-up

This challenge consists of an android app and a server component written in python. If we take a look at the source of the server component we can see the following:

```python
    def POST(self):
        try:
            orderStr = web.data()
            subIndex = orderStr.rfind('&sign=')
            signedStr = orderStr[:subIndex]
            messageHash = hashlib.sha256(signedStr).digest()
            if not(rsa.verify(signedStr, b64decode(orderStr[subIndex+6:]), pubKey)):
                raise Exception

        except:
            return json.dumps({'status':2})

        try:
            orderStrParts = orderStr.split('&')
            price = 0
            orderID = ""
            for part in orderStrParts:
                if part.startswith('price='):
                    price = int(part[6:])
                if part.startswith('orderID='):
                    orderID = part[8:]
            if price > 0:
                raise Exception

            return json.dumps({'status':4, 'data':'BCTF{XXXXXXXXXXXXXXXX}'})

        except:
            return json.dumps({'status':3})
```

So we should find the server where this is hosted and somehow trick it into processing a signed order with `price = 0`. The order routine allows us to place an order and signs it:

```python
            params = web.data()
            data = json.loads(params)
            androidID = data['androidID']
            productID = data['productID']
            if productID == 0:
                price = 50000
            elif productID == 1:
                price = 80000
            elif productID == 2:
                price = 100000
            elif productID == 3:
                price = 120000
            elif productID == 4:
                price = 500000
            else:
                raise ValueError("productID is not correct!")

            rand = random.randint(1,100000000)
            orderID = androidID + str(rand)
            timestamp = int(time.time()*1000)
            orderStr = "orderID="+orderID
            orderStr += ("&price="+str(price))
            orderStr += ("&productID="+str(productID))
            orderStr += ("&timestamp="+str(timestamp))
            orderStr += ("&signer=RSA")
            orderStr += ("&hash=sha256")

            nonce = "%016x" % random.getrandbits(64)
            orderStr += ("&nonce="+nonce)
            messageHash = hashlib.sha256(orderStr).digest()

            messageSign = rsa.sign(orderStr, privKey, 'SHA-256')
            orderStr += ("&sign="+b64encode(messageSign))

            return json.dumps({'status':1, 'data':orderStr})
        except:
            return json.dumps({'status':0})
```

As we can see it sets the price itself so we can't influence it here. Loading up the APK file in `jadx` allows us to extract the two hostnames which are used for placing orders and processing 'payments': `http://mall.godric.me` and `http://paygate.godric.me`.

Let's take a closer look at the payment data parsing routine:

```python
    orderStrParts = orderStr.split('&')
    price = 0
    orderID = ""
    for part in orderStrParts:
    if part.startswith('price='):
        price = int(part[6:])
    if part.startswith('orderID='):
        orderID = part[8:]
```

This splits the order string into parts seperated by `&` and whenever a part starts with `price=` it sets the price variable accordingly. This means that we can redefine the variable at a later point during string processing, eg. `&price=1337&price=0`. Now lets take a look at how the signing is done:

```python
    orderStr = web.data()
    subIndex = orderStr.rfind('&sign=')
    signedStr = orderStr[:subIndex]
    messageHash = hashlib.sha256(signedStr).digest()
    if not(rsa.verify(signedStr, b64decode(orderStr[subIndex+6:]), pubKey)):
        raise Exception
```

We find the signature as indicated by &sign= and extract the signed string from it as everything preceding it. This signed string is then sha256 hashed and compared against the signature embedded in the base64 encoded rest of the string. The problem lies with the above described 'variable overriding' combined with the fact that b64decode doesn't "safe decode" and ignores any non-base64 data appended to a base64 blob, eg.:

```python
b64decode(b64encode("test")+"&price=0") = 'test'
```

Here the signature will be valid over the data preceding the signature while the final appended parameter will override the price which [gives us](solution/zerodaystore_crack.py):

```bash
$ ./zerodaystore_crack.py
[+] Got flag: [BCTF{0DayL0veR1chGuy5}]
```