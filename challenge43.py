from Crypto.Random import random
import challenge39

def genP(L, q):
    minK = (2**(L-1) + q-1)//q
    maxK = (2**L - 1)//q
    while True:
        k = random.randint(minK, maxK)
        p = k*q + 1
        if challenge39.isProbablePrime(p, 5):
            return (k, p)

def genG(p, q, k):
    for h in range(2, p - 1):
        g = pow(h, k, p)
        if g != 1:
            return g
    raise Exception('unexpected')

def genParams(L, N):
    q = challenge39.getProbablePrime(N)
    k, p = genP(L, q)
    g = genG(p, q, k)
    return (p, q, g)

def areValidParams(L, N, p, q, g):
    return ((q.bit_length() == N) and
            challenge39.isProbablePrime(q, 5) and
            (p.bit_length() == L) and
            challenge39.isProbablePrime(p, 5) and
            ((p-1) % q == 0) and
            pow(g, q, p) == 1)

def genKeys(p, q, g):
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    pub = (p, q, g, y)
    priv = x
    return (pub, priv)

def areValidKeys(pub, priv):
    (p, q, g, y) = pub
    x = priv
    return y == pow(g, x, p)

if __name__ == '__main__':
    L = 1024
    N = 160
    (p, q, g) = (0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1, 0xf4f47f05794b256174bba6e9b396a7707e563c5b, 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291)
    print(p, q, g, areValidParams(L, N, p, q, g))
    (pub, priv) = genKeys(p, q, g)
    print(pub, priv, areValidKeys(pub, priv))
