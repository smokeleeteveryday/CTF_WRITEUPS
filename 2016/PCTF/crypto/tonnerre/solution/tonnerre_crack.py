#!/usr/bin/env python
#
# Plaid CTF 2016
# tonnerre (CRYPTO/200)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from Crypto.Hash import SHA256

# GCD (times sign of b if b is nonzero, times sign of a if b is zero)
def gcd(a,b):
  while b != 0:
      a,b = b, a % b
  return a

# Extended Greatest Common Divisor
def egcd(a, b):
  if (a == 0):
      return (b, 0, 1)
  else:
      g, y, x = egcd(b % a, a)
      return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
  g, x, y = egcd(a, m)
  if (g != 1):
      raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
  else:
      return x % m

def H(P):
  h = SHA256.new()
  h.update(P)
  return h.hexdigest()

def tostr(A):
  return hex(A)[2:].strip('L')

N = 168875487862812718103814022843977235420637243601057780595044400667893046269140421123766817420546087076238158376401194506102667350322281734359552897112157094231977097740554793824701009850244904160300597684567190792283984299743604213533036681794114720417437224509607536413793425411636411563321303444740798477587L
g = 9797766621314684873895700802803279209044463565243731922466831101232640732633100491228823617617764419367505179450247842283955649007454149170085442756585554871624752266571753841250508572690789992495054848L
verifier = long('ebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59', 16)

public_client = (pow(g, 2) * modInv(verifier, N)) % N

assert (((public_client * verifier) % N) == pow(g, 2, N))

print "public_client> [%s]" % (tostr(public_client))

residue = raw_input('Residue?> ')
residue_l = long(residue, 16)
session_secret = pow(residue_l - verifier, 2, N)
session_key = H(tostr(session_secret))
print "proof> [%s]" % H(tostr(residue_l) + session_key)