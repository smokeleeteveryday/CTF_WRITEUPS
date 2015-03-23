#!/usr/bin/python
#
# BCTF 2015
# WEAK_ENC (CRYPTO/200) cracker
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import socket
import re
import base64 as b64
import hashlib
import itertools
import string

SMALLPRIME = 13
HASHLENGTH = 16
N = 17

# Get SHA1
def getSHA(data):
	ha = hashlib.sha1()
	ha.update(data)
	return ha.digest()

# Do proof of work
def findSHA(challenge):
	charset = "".join(chr(i) for i in range(0x00, 0x100))
	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(5, 5 + 1)):
		candidate = challenge + p
		proof = getSHA(candidate)
		if((ord(proof[-2]) == 0) and (ord(proof[-1]) == 0)):
			return candidate
	return None

# Session with server
def talk(s, plaintext):
	workrequest = s.recv(1024) 
	if not workrequest:
		return None

	m = re.match(r"^.*with\s(.*?)$", workrequest, re.MULTILINE)

	if not(m):
		return None

	challenge = m.group(1)	
	response = findSHA(challenge)

	s.sendall(response)
	welcome = s.recv(1024)
	
	if not welcome:
		return None

	s.sendall(plaintext + "\n")
	encrypted = s.recv(1024)

	if not encrypted:
		return None

	m = re.match(r"^.*:\s(.*?)$", encrypted, re.MULTILINE)
	if not(m):
		return None

	ciphertext = m.group(1)
	return ciphertext

# Do request
def req(HOST, m):
	PORT = 8888
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	ciphertext = talk(s, m)
	s.close()
	return ciphertext

# Update LZW Dict
def updateDict(s, lzwDict):
    if not s in lzwDict:
        count = len(lzwDict.keys())
        lzwDict[s] = count % 256

# LZW
def LZW(s, lzwDict): # LZW written by NEWBIE
    for c in s: updateDict(c, lzwDict)
    # print lzwDict # have to make sure it works
    result = []
    i = 0
    while i < len(s):
        if s[i:] in lzwDict:
            result.append(lzwDict[s[i:]])
            break
        for testEnd in range(i+2, len(s)+1):
            if not s[i:testEnd] in lzwDict:
                updateDict(s[i:testEnd], lzwDict)
                result.append(lzwDict[s[i:testEnd-1]])
                i = testEnd - 2
                break
        i += 1
    return result

# PRNG
def STRONGPseudoRandomGenerator(s):
    return s[SMALLPRIME - HASHLENGTH :], hashlib.md5(s).digest()

# Get OTPBase
def getOTPBase(SALT):
	key = hashlib.md5(SALT*2).digest()
	OTPBase = ""
	OPT = ""
	step = HASHLENGTH - SMALLPRIME
	for i in range(0, 3*N+step, step):
		rand, key = STRONGPseudoRandomGenerator(key)
		OTPBase += rand
	return OTPBase

# Encryption function
def encrypt(SALT, m):
    lzwDict = dict()
    toEnc = LZW(SALT + m, lzwDict)
    key = hashlib.md5(SALT*2).digest()
    OTPBase = ""
    OPT = ""
    step = HASHLENGTH - SMALLPRIME
    for i in range(0, 3*N+step, step):
        rand, key = STRONGPseudoRandomGenerator(key)
        OTPBase += rand
    enc = []
    otpadded = []
    for i in range(len(toEnc)):
        index = i % N
        iRound = i / N + 1
        OTP = OTPBase[3*int(pow(ord(OTPBase[3*index]),ord(OTPBase[3*index+1])*iRound, N))+2]
        otpadded.append(ord(OTP))
        enc.append(chr(toEnc[i] ^ ord(OTP)))
    return b64.b64encode(''.join(enc))

# Obtain LZW compressed message length
def lzwCompressLen(m):
	lzwDict = dict()
	return len(LZW(m, lzwDict))

# Obtain LZW dictionary
def lzwDict(SALT, m):
	lzwDict = dict()
	LZW(SALT+m, lzwDict)
	return lzwDict

# Check if n-gram is in LZW dictionary
def checkTuple(HOST, nulllen, prefix, charset, tuplelen):
	tuples = []
	for p in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(tuplelen, tuplelen + 1)):
		ctext = req(HOST, prefix+p)
		if(len(b64.b64decode(ctext)) - nulllen == 1):
			tuples.append(prefix+p)
	return tuples

# Obtain LZW dictionary n-grams
def getTuples(HOST, nulllen, prefixes, charset, tuplelen):
	tuples = []
	if(len(prefixes) > 0):
		for prefix in prefixes:
			tuples += checkTuple(HOST, nulllen, prefix, charset, tuplelen)
		return tuples
	else:
		return checkTuple(HOST, nulllen, "", charset, tuplelen)

# Obtain SALT given n-gram its composition
def getSALT(charset, nulllen):
	for candidate in itertools.chain.from_iterable((''.join(l) for l in itertools.product(charset, repeat=i)) for i in range(1, nulllen + 1)):
		if(nulllen == lzwCompressLen(candidate)):
			if(nullcipher == encrypt(candidate, "")):
				return candidate
	return None

# Recover LZW compressed message given OTPBase
def recoverLZWCompress(c, OTPBase):
	enc = list(b64.b64decode(c))
	toEnc = []

	for i in range(len(enc)):
		index = i % N            # index within the round (0..16)
		iRound = i / N + 1       # round index (1 for 0..16, 2 for 17..31, etc.)
		OTP = OTPBase[3*int(pow(ord(OTPBase[3*index]),ord(OTPBase[3*index+1])*iRound, N))+2]
		toEnc.append(ord(enc[i]) ^ ord(OTP))
	return toEnc

HOST = '146.148.79.13'
ciphertext = "NxQ1NDMYcDcw53gVHzI7"
cipherlen = len(b64.b64decode(ciphertext))

print "[*]Target ciphertext: [%s] (%d bytes)" % (b64.b64decode(ciphertext).encode('hex'), cipherlen)

# Obtain null cipher
nullcipher = req(HOST, "")
nulllen = len(b64.b64decode(nullcipher))
maxplainlen = cipherlen - nulllen

print "[+]Null cipher: [%s]" % nullcipher
print "[+]Null len: %d" % nulllen
print "[+]Max LZW plaintext len: %d" % maxplainlen

# SALT charset
charset = string.ascii_lowercase

print "[*]Reconstructing LZW dictionary n-grams..."

# Get initial dictionary bi-grams
tupleset = getTuples(HOST, nulllen, [], charset, 2)
tupget = tupleset
# Retrieve dictionary n-grams as long as possible
while (len(tupget) > 0):
	tupget = getTuples(HOST, nulllen, tupget, charset, 1)
	tupleset += tupget

print "[*]Recovering SALT..."

# Recover SALT, this could be done more efficiently by determinig order of n-gram occurance but who cares
SALT = getSALT(tupleset, nulllen)
# Derive OTPBase
OTPBase = getOTPBase(SALT)
# Recover compressed message
recComp = recoverLZWCompress(ciphertext, OTPBase)
# Reconstruct SALT LZW dictionary
saltDict = lzwDict(SALT, "")
revSaltDict = dict((v, k) for k, v in saltDict.items())

print "[+]Got SALT: [%s]" % SALT
print "[+]Got OTPBase: [%s]" % OTPBase.encode('hex')
print "[+]Got LZW compressed message: [%s]" % (",".join(str(i) for i in recComp))

# Derive plaintext message
message = ""
for i in range(nulllen, len(recComp)):
	if not(recComp[i] in revSaltDict):
		print "[-]Element isn't in reconstructed LZW dictionary..."
		exit()
	
	message += revSaltDict[recComp[i]]

if(encrypt(SALT, message) == ciphertext):
	print "[+]Recovered message plaintext: [%s]" % message
else:
	print "[-]Something went wrong..."