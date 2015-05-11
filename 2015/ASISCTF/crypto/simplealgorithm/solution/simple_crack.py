#!/usr/bin/python
#
# ASIS CTF Quals 2015
# simple algorithm (CRYPTO/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

# FAN encoding routine
def FAN(n, m):
    i = 0
    z = []
    s = 0
    while n > 0:
        if n % 2 != 0:
            z.append(2 - (n % 4))
        else:
            z.append(0)
        n = (n - z[i])/2
        i = i + 1
    z = z[::-1]
    l = len(z)
    for i in range(0, l):
        s += z[i] * m ** (l - 1 - i)
    return s

# Inverse of FAN encoding routine
def DEFAN(s, m):
    z = []
    while(s != 0):
        zi = s % m
        if(zi == 2):
            zi = -1

        z.append(zi)
        s -= zi
        s /= m
    z = z[::-1]
    for i in xrange(len(z)):
        if(i == 0):
            n = z[i]
        else:
            n = 2*n + z[i]
    return n

# Decrypt re-segmented ciphertext
def decrypt(r, m):
    q = ''
    for i in xrange(0, len(r)):
        d = str(DEFAN(long(r[i]), m))
        if((len(d) < 2) and (i != (len(r)-1))):
            d = '0'+d
        q += d
    return hex(long(q))[2:-1].decode('hex')

# All possible values for FAN encoding routine
def getR(m):
    R = []
    for i in xrange(0, 100):
        d = str(i)
        if(len(d) < 2):
            d = '0'+d

        q = FAN(int(d), m)
        R.append(q)
    return R

# Re-segment encoded string based on greedy approach
def segment(e, m):
    R = getR(m)
    offset = 0
    s = []
    while(offset < len(e)):
        for i in xrange(4, 0, -1):
            chunk = e[offset: offset+i]
            if(long(chunk) in R):
                s.append(chunk)
                offset += i
                break
    return s

m = 3
eflag = open("enc.txt", "rb").read()

print "[+]Got flag: [%s]" % decrypt(segment(eflag, m), m)