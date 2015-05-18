#!/usr/bin/python
#
# DEF CON CTF Quals 2015
# accesscontrol (REVERSING/1)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
from struct import unpack

def get_password(a1, connection_id, conn_id_index, dword_804BC80):
	a2 = ""

	offset = conn_id_index + (dword_804BC80 % 3)
	dest = connection_id[offset: offset+5]

	for i in xrange(5):
		a2 += chr(ord(dest[i]) ^ ord(a1[i]))
	return a2

def decode_password(a1):
	result = list()
	a2 = list(a1)
	for i in xrange(5):
		if(ord(a2[i]) <= 31):
			a2[i] = chr(ord(a2[i]) + 32)
		result = a2[i]
		if(ord(result) == 127):
			a2[i] = chr(ord(a2[i]) - 126)
			result = a2[i: ]
			a2[i] = chr(ord(a2[i]) + 32)
	return result, "".join(a2)

def handshake(h):
	version = "version 3.11.54"
	msg = h.recvuntil("what version is your client?\n")
	c_offset = msg.find("connection ID: ")
	connection_id = msg[c_offset+15: c_offset+29]
	h.send(version + "\n")
	msg = h.recvuntil("hello...who is this?\n")
	return connection_id

def login(h, username, connection_id, conn_id_index, dword_804BC80, hello_str):
	h.send(username + "\n")
	msg = h.recvuntil("enter user password\n")

	pwd = get_password(username, connection_id, conn_id_index, dword_804BC80)
	res, pwd = decode_password(pwd)

	print "Password: [%s]" % pwd

	password = "%s" % pwd
	h.send(password + "\n")
	msg = h.recvuntil(hello_str)
	return True

def list_users(h):
	h.send("list users\n")
	msg = h.recvuntil("deadwood\n")

	print "Users: [%s]" % msg
	return

def print_key_challenge(h, connection_id, dword_804BC80):
	h.send("print key\n")
	msg = h.recv(2048)

	c_offset = msg.find("challenge: ")
	challenge = msg[c_offset+11: c_offset+16]

	print "Challenge: [%s]" % challenge

	msg = h.recvuntil("answer?\n")
	conn_id_index = 7
	pwd = get_password(challenge, connection_id, conn_id_index, dword_804BC80)
	conn_id_index = 1
	res, pwd = decode_password(pwd)

	response = pwd[0: 5]
	h.send(response + "\n")

	msg = h.recv(2048)
	
	offset = msg.find("the key is: ")
	key = msg[offset+12: ]
	print "Key: [%s]" % key
	return

username = "duchess"
client_state = 0
conn_id_index = 1
dword_804BC80 = 0
hello_str = "hello %s, what would you like to do?\n" % username

host = 'access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me'
port = 17069

h = remote(host, port, timeout = None)

while(True):
	if(client_state == 0):
		connection_id = handshake(h)
		print "Connection ID: [%s]" % connection_id
		second_dword = connection_id[4: 8]
		dword_804BC80 = unpack('B', second_dword[3])[0]
		client_state = 1
	elif(client_state == 1):
		if(login(h, username, connection_id, conn_id_index, dword_804BC80, hello_str)):
			client_state = 2
		else:
			raise Exception("[-]Incorrect login for '%s'" % username)
	elif(client_state == 2):
		print_key_challenge(h, connection_id, dword_804BC80)
		break

h.close()