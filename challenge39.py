from Crypto.Random import random

primes = [5, 7, 11, 13, 17, 19]

def invmod(a, n):
    t = 0
    newt = 1
    r = n
    newr = a
    while newr != 0:
        q = r // newr
        (t, newt) = (newt, t - q * newt)
        (r, newr) = (newr, r - q * newr)
    if r > 1:
        raise Exception('unexpected')
    if t < 0:
        t += n
    return t

def genKey():
    e = 3

    p = 7
    while (p - 1) % e == 0:
        p = random.choice(primes)

    q = p
    while q == p or (q - 1) % e == 0:
        q = random.choice(primes)

    n = p * q
    et = (p - 1) * (q - 1)
    d = invmod(e, et)
    pub = (e, n)
    priv = (d, n)
    return (pub, priv)

def encryptnum(pub, m):
    (e, n) = pub
    if m < 0 or m >= n:
        raise ValueError(str(m) + ' out of range')
    return pow(m, e, n)

def decryptnum(priv, c):
    (d, n) = priv
    if c < 0 or c >= n:
        raise ValueError(str(c) + ' out of range')
    return pow(c, d, n)

if __name__ == '__main__':
    pub, priv = genKey()
    m = 42
    c = encryptnum(pub, m)
    m2 = decryptnum(priv, c)
    if m != m2:
        raise Exception(str(m) + ' != ' + str(m2))
