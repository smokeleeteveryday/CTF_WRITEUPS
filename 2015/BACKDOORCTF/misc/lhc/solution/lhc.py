#!/usr/bin/python
#
# Backdoor CTF 2015
# LHC (MISC/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
import urllib2

area_size = 1024
target_url = 'https://lhc-cdn.herokuapp.com/data.txt'

# Get total file length in advance
def getFlen(url):
	req = urllib2.Request(url)
	f = urllib2.urlopen(req)
	meta = f.info()
	return meta.getheaders("Content-Length")[0]

# Get segment of remote file
def getData(url, offset_start, offset_end):
	req = urllib2.Request(url)
	req.headers['Range'] = 'bytes=%s-%s' % (offset_start, offset_end)
	f = urllib2.urlopen(req)
	return f.read()

flen = long(getFlen(target_url))

print "[*]Total file length: %d" % flen

offset_start = long(flen / 2) - area_size
offset_end = offset_start + (area_size*2)

print "[*]Fetching from offset %d to %d" % (offset_start, offset_end)

data = getData(target_url, offset_start, offset_end)
print data