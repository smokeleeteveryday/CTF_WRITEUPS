#!/usr/bin/env python
#
# CSAWCTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from pwn import *
import string

# Alphanumeric alphabet (ordered by ASCII value)
charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
solution = ""

# Recursive version of hash function (as reversed)
def hashf(inp):
    # Multiplier
    M = 0x21
    # Modulus
    P = 2**32
    # Initial state
    state = 0x1505
    for c in inp:
        state = ((state * M) + ord(c)) % P
    return state

# Fetches candidate characters for a given position
def index_candidate_chars(target, candidate, index):
    global charset, solution

    r = []

    # Start out with lowest ASCII value
    tmp_candidate = list(candidate)
    tmp_candidate[index] = charset[0]
    tmp_candidate = "".join(tmp_candidate)
    p_hash = hashf(tmp_candidate)

    # Work through entire character set
    for j in xrange(1, len(charset)):
        tmp_candidate = list(tmp_candidate)
        tmp_candidate[index] = charset[j]
        tmp_candidate = "".join(tmp_candidate)
        n_hash = hashf(tmp_candidate)

        # Have we found it?
        if(n_hash == target):
            print "[+]Cracked input: [%s] (0x%x)" % (tmp_candidate, n_hash)
            solution = tmp_candidate
            return None

        # If the target is in between the previous and current hash value we consider the previous character a candidate for this position
        if ((p_hash < target) and (target < n_hash)):
            r.append(charset[j-1])

        p_hash = n_hash

    return r + [charset[len(charset)-1]]

# Recursive cracking function
def crack(target, candidate, index):
    global charset

    if (index >= len(candidate)):
        return

    chars = index_candidate_chars(target, candidate, index)
    
    if(chars == None):
      return True

    # Branch out over all candidate characters at this position
    for c in chars:
        tmp_candidate = list(candidate)
        tmp_candidate[index] = c
        tmp_candidate = "".join(tmp_candidate)
        status = crack(target, tmp_candidate, index + 1)
        if(status):
          return True

    return False

# Target hash
h = 0xD386D209

print "[*]Cracking h = 0x%x" % h

# Try different lengths
min_len = 1
max_len = 20

for i in xrange(min_len, max_len+1):
    print "[*]Trying length %d..." % i
    # Initial candidate (lowest cumulative value)
    candidate = charset[0]*i
    if(crack(h, candidate, 0)):
      break

# Log in to FTP
username = "blankwall"
password = solution + "\x00"

host = '54.175.183.202'
port = 12012

h = remote(host, port, timeout = None)

msg = h.recv(1024)

print msg

h.sendline("USER " + username)
msg = h.recv(1024)
print msg

h.sendline("PASS " + password)
msg = h.recv(1024)
print msg

msg = h.recv(1024)
print msg

h.sendline("SYST")
msg = h.recv(1024)
print msg

h.sendline("PWD")
msg = h.recv(1024)
print msg

# Flag request command

h.sendline("RDF")
msg = h.recv(1024)
print msg

msg = h.recv(1024)
print msg

h.close()