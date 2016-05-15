#!/usr/bin/env python

def to_bits(length, N):
    return [int(i) for i in bin(N)[2:].zfill(length)]

def from_bits(N):
    return int("".join(str(i) for i in N), 2)

CONST2 = to_bits(65, (2**64) + 0x1fe67c76d13735f9)
CONST = to_bits(64, 0xabaddeadbeef1dea)

def hash_n_bake(mesg):
    mesg += CONST
    shift = 0
    while shift < len(mesg) - 64:
        if mesg[shift]:
            for i in range(65):
                mesg[shift + i] ^= CONST2[i]
        shift += 1
    return mesg[-64:]

def xor(x, y):
    return [g ^ h for (g, h) in zip(x, y)]

PLAIN_1 = "goatscrt"
PLAIN_2 = "tu_ctf??"

def str_to_bits(s):
    return [b for i in s for b in to_bits(8, ord(i))]

def bits_to_hex(b):
    return hex(from_bits(b)).rstrip("L")

if __name__ == "__main__":
    with open("key.txt") as f:
        KEY = to_bits(64, int(f.read().strip("\n"), 16))
    print PLAIN_1, "=>", bits_to_hex(hash_n_bake(xor(KEY, str_to_bits(PLAIN_1))))
    print "TUCTF{" + bits_to_hex(hash_n_bake(xor(KEY, str_to_bits(PLAIN_2)))) + "}"

#  Output
#  goatscrt => 0xfaae6f053234c939
#  TUCTF{****REDACTED****}
