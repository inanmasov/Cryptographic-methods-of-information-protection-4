import random
from Crypto.Util.number import getPrime
from asn1 import Encoder, Numbers


def is_prime(num):
    if num == 2:
        return True
    if num % 2 == 0:
        return False
    i = 0
    while i < 100:
        a = random.randint(1, num - 1)
        if pow(a, num - 1, num) != 1:
            return False
        i += 1
    return True


def GenParam(bits):
    while 1:
        p = getPrime(bits)
        a = random.randint(2, p - 1)
        r = p - 1

        if pow(a, r, p) != 1 or pow(a, (p - 1) // r, p) == 1:
            continue

        #for i in range(1, r+1):
            #print(pow(a, i, p))

        print('r =', r)
        print('a =', a)

        return r, a


def save_asn1_client(A_pub, a, r):
    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Set)
    asn1.enter(Numbers.Sequence)
    asn1.write(b'\x00\x21', Numbers.OctetString)
    asn1.write('dh', Numbers.UTF8String)
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(r, Numbers.Integer)
    asn1.write(a, Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(A_pub, Numbers.Integer)
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.leave()

    with open("client.asn1", "wb") as file:
        file.write(asn1.output())


def save_asn1_server(B_pub):
    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Set)
    asn1.enter(Numbers.Sequence)
    asn1.write(b'\x00\x21', Numbers.OctetString)
    asn1.write('dh', Numbers.UTF8String)
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(B_pub, Numbers.Integer)
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.leave()

    with open("server.asn1", "wb") as file:
        file.write(asn1.output())


def diffie_hellman():
    r, a = GenParam(1024)

    x = random.randint(1, r - 1)
    print('x =', x)
    A_pub = pow(a, x, r)

    save_asn1_client(A_pub, a, r)

    y = random.randint(1, r - 1)
    print('y =', y)
    B_pub = pow(a, y, r)

    save_asn1_server(B_pub)

    K_A = pow(B_pub, x, r)
    K_B = pow(A_pub, y, r)

    if K_A == K_B:
        return K_A
    else:
        return False

if __name__ == '__main__':
    print('key =', diffie_hellman())