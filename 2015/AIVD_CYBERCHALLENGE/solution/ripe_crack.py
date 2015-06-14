#!/usr/bin/env python
#
# AIVD Cyber Challenge 2015 (BONUS)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import hashlib
import itertools
import string

def ripemd160(indata):
	h = hashlib.new('ripemd160')
	h.update(indata)
	return h.hexdigest()

def brute(prefix, crack_len, target):
	# lower+upper alphanumeric
	charset = string.letters + string.digits

	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(crack_len, crack_len + 1)):
		if(ripemd160(prefix + p) == target):
			return prefix + p
	return ""

leak_fragments = [(5, "38fd30d7441a1bd1490a2ba91f0e4a73495640d7"),
(7, "7b4ceb50c1bb181033dc4dd0080b1ddc98b46f29"),
(9, "66702342d69133a92d303edc497115642aa995f8"),
(11, "3c5008ab11ce269c2412536e53008aabf7246a4e"),
(13, "8f466d257e3cc71b0a2b355fa0bb1e16a8aa5ead"),
(15, "c18428c4ac0295f605acd953d0c0490a4b22a51c"),
(17, "38ada7dc4355a76351affe64657450d347e10349"),
(19, "ffe4582900b994a3863d96775fd1964c80fa6392"),
(21, "cf0fdb641b0df6ec6231efc142891c92986178dc"),
(23, "c5f6aba5c5ddb6fc30aa1a20a96dac5cc6a88677"),
(25, "16ed8ef5a657bc26bfeeaa4a30bed8b76a128c4e"),
(27, "16d5826bebc39b70b9e12529d50fef09c938d001"),
(29, "43cdb8c07847f1087da7e611125afc1ffa801ad9"),
(31, "0fe5cf679ef26ab27b1e5bbb6b4176d67e4c154e")]

# We know the first 5 bytes because they match the ones output by our binary
password = "EX382"
for fragment in leak_fragments:
	password = brute(password, fragment[0] - len(password), fragment[1])

	if(password == ""):
		raise Exception("[-]Couldn't crack (%d, %s) :(" % (fragment[0], fragment[1]))

print "[+]Got password: [%s]!" % password