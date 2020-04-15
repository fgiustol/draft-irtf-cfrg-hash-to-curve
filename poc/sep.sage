#!/usr/bin/sage
# vim: syntax=python

import EccCore
import hashlib
import random
from sagelib.suite_secp256k1 import secp256k1_svdw_ro

#curve for hash_to_curve
suite=secp256k1_svdw_ro

#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
a = 0
b = 7
#base point on the curve
base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]

secretKey=random.getrandbits(256)
publicKey = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], secretKey, a, b, mod)


def send_bait():
    msg=random.getrandbits(256)
    vector = suite(str(msg), output_test_vector=True) 
    randomKey = random.getrandbits(256)
    c1 = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], randomKey, a, b, mod)
    c2 = (int(vector["P"][0]), int(vector["P"][1]))
    return c1,c2


def send_bit(b):
    while True:
        plaintext=random.getrandbits(256)
        plain_coordinates = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], plaintext, a, b, mod)
        hpc=hashlib.sha256()
        hpc.update(str(plain_coordinates[0]).encode())
        hpc.update(str(plain_coordinates[1]).encode())
        hpc_dig=hpc.digest()
        this_b=hpc_dig[31]&1
        if this_b==b:
            randomKey = random.getrandbits(256)
            c1 = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], randomKey, a, b, mod)
            c2 = EccCore.applyDoubleAndAddMethod(publicKey[0], publicKey[1], randomKey, a, b, mod)
            c2 = EccCore.pointAddition(c2[0], c2[1], plain_coordinates[0], plain_coordinates[1], a, b, mod)
            return c1,c2


def decrypt(c1,c2):
    #secret key times c1
    dx, dy = EccCore.applyDoubleAndAddMethod(c1[0], c1[1], secretKey, a, b, mod)
    #-secret key times c1
    dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found

    #c2 + secret key * (-c1)
    decrypted = EccCore.pointAddition(c2[0], c2[1], dx, dy, a, b, mod)
    hpc2=hashlib.sha256()
    hpc2.update(str(decrypted[0]).encode())
    hpc2.update(str(decrypted[1]).encode())
    hpc2_dig=hpc2.digest()
    b2=hpc2_dig[31]&1
    print(b2,end='')

print("Loading...")
ins=input("Enter a string of bits and baits (0,1,b): ")
for x in ins:
    if x=='0' or x=='1': 
        c1,c2=send_bit(int(x))
    else:
        c1,c2=send_bait()
    decrypt(c1,c2)

