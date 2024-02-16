from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse
from asn1 import Encoder, Numbers
from math import gcd
import random


def GenParam(bits):
    while 1:
        p = getPrime(bits)
        a = random.randint(2, p - 1)
        r = (p - 1) // 2

        if pow(a, r, p) != 1 or pow(a, (p - 1) // r, p) == 1:
            continue

        x = random.randint(2, r)
        b = pow(a, x, p)

        return p, a, r, x, b


def ElGamalSignature(p, a, r, x, m):
    k = random.randint(1, r)
    while gcd(k, r) != 1:
        k = random.randint(1, r)
    #print("k = %d" % k)

    hash = SHA256.new(m)
    print('hash =', hash.hexdigest())
    h = int(hash.hexdigest(), 16)

    w = pow(a, k, p)
    s = ((h - x * w) * inverse(k, r)) % r

    return w, s


def save_asn1(p, a, b, r, w, s):
    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Set)
    asn1.enter(Numbers.Sequence)
    asn1.write(b'\x80\x06\x02\x00', Numbers.OctetString)
    asn1.enter(Numbers.Sequence)
    asn1.write(b, Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(p, Numbers.Integer)
    asn1.write(r, Numbers.Integer)
    asn1.write(a, Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(w, Numbers.Integer)
    asn1.write(s, Numbers.Integer)
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.leave()

    with open("sign.asn1", "wb") as file:
        file.write(asn1.output())


def SignatureVerification(m, p, a, b, w, s):
    if w >= p:
        print("Signature not accepted")
        return

    hash = SHA256.new(m)
    h = int(hash.hexdigest(), 16)

    if pow(a, h, p) % p == (pow(b, w, p) * pow(w, s, p)) % p:
        print("Signature accepted")
    else:
        print("Signature not accepted")


if __name__ == '__main__':
    p, a, r, x, b = GenParam(1024)
    print("p = %d" % p)
    print("a = %d" % a)
    print("b = %d" % b)
    print("r = %d" % r)
    print("x = %d" % x)

    with open('file.txt', "rb") as file:
        m = file.read()

    w, s = ElGamalSignature(p, a, r, x, m)
    save_asn1(p, a, b, r, w, s)
    SignatureVerification(m, p, a, b, w, s)