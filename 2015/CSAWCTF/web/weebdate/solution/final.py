#!/usr/bin/env python

import hashlib, pyotp,random, itertools, socket, struct, string

#{'report_ip': u'2', 'report_content': u'3', 'report_id': u'5:::donaldtrump:::22e59a7a2792b25684a43d5f5229b2b5caf7abf8fa9f186249f35cae53387fa3:::64.124.192.210:::http://i.imgur.com/6ebAqqF.png:::0:::0'}
# We need to know the totp key, for that we need the seed:

def generate_seed(username, ip_address):
    return int(struct.unpack('I', socket.inet_aton(ip_address))[0]) + struct.unpack('I', username[:4].ljust(4,'0'))[0]

def get_totp_key(seed):
    random.seed(seed)
    return pyotp.random_base32(16, random)

username = "donaldtrump"
ip_address="64.124.192.210"

# generate totp_key
seed = generate_seed(username, ip_address)
totp_key = get_totp_key(seed)

print "[+]Recovered totp_key: [%s] " % totp_key

# and we need to find the password, which is:
secret_hash = "22e59a7a2792b25684a43d5f5229b2b5caf7abf8fa9f186249f35cae53387fa3"
file = "john.txt"
f = open(file, "r")
final_password = ""
for password in f:
	password = password.strip()
	candidate = hashlib.sha256(username+password).hexdigest()
	if candidate == secret_hash:
		print "[+]Cracked password [ %s ] " % password
		final_password = password
		break

flag = hashlib.md5(totp_key+final_password).hexdigest()
print "[+]Flag: [%s]" % flag
