#!/usr/bin/python
#
# Teaser CONFidence CTF 2015
# Mac Hacking (CRYPTO/150)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import requests
import hmac
from hashlib import md5
from urllib import urlencode
import hashpumpy

blocksize = md5().block_size

def visit(url, encoded_args):
	r = requests.get(url + "?" + encoded_args)
	return r.text.strip()

def oldSign(url, data):
	args = {'a': 'sign',
			'm': 'old',
			'd': data}
	return visit(url, urlencode(args))

def newVerify(url, data, signature):
	args = {'a': 'verify',
			'm': 'new',
			'd': data,
			's': signature}
	return visit(url, urlencode(args))

url = "http://95.138.166.219/"

base_msg = "ayylmao"
extend_msg = "get flag"

i_key_md5 = oldSign(url, "\x36"*blocksize + base_msg).decode('hex')
print "[+]Got md5(i_key_pad + '%s') = %s" % (base_msg, i_key_md5.encode('hex'))

res = hashpumpy.hashpump(i_key_md5.encode('hex'), base_msg, extend_msg, blocksize)
i_key_md5_extend = res[0]
forged_msg = res[1]

print "[+]Got md5(i_key_pad + '%s') = %s" % (forged_msg, i_key_md5_extend)

o_key_md5 = oldSign(url, "\x5C"*blocksize + i_key_md5_extend.decode('hex'))

print "[+]Got md5(o_key_pad + md5(i_key_pad + forged_msg).digest()) = %s" % o_key_md5
print "[+]Verification response: [%s]" % newVerify(url, forged_msg, o_key_md5)