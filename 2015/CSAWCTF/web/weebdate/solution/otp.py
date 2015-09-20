#!/usr/bin/env python

from otpauth import OtpAuth
import time, base64

secret = "QDQQFZ6AUZQ2YR6N" # key for gooby:1
auth = OtpAuth(base64.b32decode(secret))
print "[+]User: gooby, password:1"
print "[+]TOTP token: [%d]" % auth.totp()
print "[+]%s " % time.strftime("%c")
