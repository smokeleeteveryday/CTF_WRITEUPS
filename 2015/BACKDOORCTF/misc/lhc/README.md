# Backdoor CTF 2015: LHC

**Category:** Misc
**Points:** 100
**Description:** 

> The flag is in the middle of [this dataset](https://lhc-cdn.herokuapp.com/data.txt) kindly provided to us by the Large Hadron Collider.

## Write-up

We started out by simply trying to download the file only to see it was 2TB which is far to large to be intended to be downloaded. The trick is (hinted at by saying the flag is 'in the middle') to only download part of the file starting from a given offset. This can be [done](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35) by specifying:

>Range: bytes=0-7

In your header if we want to download 8 bytes starting from offset 0. Given that we want to download some part in the middle we figured to download 2048 bytes (just a guess) around the middle of the file using [this script](solution/lhc.py):

>```python
>#!/usr/bin/python
>#
># Backdoor CTF 2015
># LHC (MISC/100)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>import urllib2
>
>area_size = 1024
>target_url = 'https://lhc-cdn.herokuapp.com/data.txt'
>
># Get total file length in advance
>def getFlen(url):
>	req = urllib2.Request(url)
>	f = urllib2.urlopen(req)
>	meta = f.info()
>	return meta.getheaders("Content-Length")[0]
>
># Get segment of remote file
>def getData(url, offset_start, offset_end):
>	req = urllib2.Request(url)
>	req.headers['Range'] = 'bytes=%s-%s' % (offset_start, offset_end)
>	f = urllib2.urlopen(req)
>	return f.read()
>
>flen = long(getFlen(target_url))
>
>print "[*]Total file length: %d" % flen
>
>offset_start = long(flen / 2) - area_size
>offset_end = offset_start + (area_size*2)
>
>print "[*]Fetching from offset %d to %d" % (offset_start, offset_end)
>
>data = getData(target_url, offset_start, offset_end)
>print data
>```

Which produces the output

>```bash
>$ python lhc.py
>(..junk..)
>■δy♥.              The flag is: bf16dc27625b189a2b0f2c52850890fac00189c0b88a2847e36facf8071df1b4       Ö╟╟
>(..junk..)
>```