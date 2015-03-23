import os, sys
import binascii
import SocketServer
import base64 as b64
import hashlib
import string
SALT = "nikonikoninikonikoni"
DEBUG= False
MSGLENGTH = 40000
SMALLPRIME = 13
HASHLENGTH = 16
N = 17
# Check salt
for i in SALT:
    if not i in string.ascii_lowercase:
        print "OMG, this salt is HOOOOOOOOOOT!!!" # Bad things happened
        sys.exit(0)

def updateDict(s, lzwDict):
    if not s in lzwDict:
        count = len(lzwDict.keys())
        lzwDict[s] = count % 256

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

def salted(m):
    cyclesalt = SALT * (len(m)/len(SALT) + 1)
    return "".join([ m[i] + cyclesalt[i] for i in range(len(m)) ])

def STRONGPseudoRandomGenerator(s):
    return s[SMALLPRIME - HASHLENGTH :], hashlib.md5(s).digest()

def encrypt(m):
    lzwDict = dict()
    toEnc = LZW(SALT + m, lzwDict)
    if DEBUG:
        print "[*]toEnc: ", toEnc
    key = hashlib.md5(SALT*2).digest()
    OTPBase = ""
    OPT = ""
    step = HASHLENGTH - SMALLPRIME
    for i in range(0, 3*N+step, step):
        rand, key = STRONGPseudoRandomGenerator(key)
        OTPBase += rand
    enc = []
    otpadded = []
    if DEBUG:
        print "[*]OTPBase: ", OTPBase.encode('hex')
    for i in range(len(toEnc)):
        index = i % N
        iRound = i / N + 1
        OTP = OTPBase[3*int(pow(ord(OTPBase[3*index]),ord(OTPBase[3*index+1])*iRound, N))+2]
        #if DEBUG:
        #print "%d = 3*int(pow(%d, %d*%d, %d)+2" % (3*int(pow(ord(OTPBase[3*index]),ord(OTPBase[3*index+1])*iRound, N))+2, ord(OTPBase[3*index]), ord(OTPBase[3*index+1]), iRound, N)
        otpadded.append(ord(OTP))
        enc.append(chr(toEnc[i] ^ ord(OTP)))
    return b64.b64encode(''.join(enc))

class HandleCheckin(SocketServer.StreamRequestHandler):
    def handle(self):
        req = self.request
        proof = b64.b64encode(os.urandom(12))

        req.sendall("Please provide your proof of work, a sha1 sum ending in 16 bit's set to 0, it must be of length %s bytes, starting with %s\n" % (len(proof)+5, proof))
        
        test = req.recv(21)
        ha = hashlib.sha1()
        ha.update(test)

        if (test[0:16] != proof or ord(ha.digest()[-1]) != 0 or ord(ha.digest()[-2]) != 0):
            req.sendall("Check failed")
            req.close()
            return
        req.sendall("=== Welcome to WEAK Encryption server ===\nPlease input your message:")
        msg = self.rfile.readline().strip()
        if DEBUG:
            print "[*]msg: [%s]" % msg
        if len(msg)>MSGLENGTH:
            req.sendall("what r u do'in?")
            req.close()
            return
        req.sendall("Your encrypted text: " + encrypt(msg) + "\n")

class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = "", int(8888)
    server = ThreadedServer((HOST, PORT), HandleCheckin)
    server.allow_reuse_address = True
    server.serve_forever()