from Crypto.Random import random
import challenge39

pub, priv = challenge39.genKey(256)

def parityOracle(c):
    _, n = pub
    k = (n.bit_length() + 7) // 8
    p = challenge39.decryptnum(priv, c)
    pbytes = challenge39.numtobytes(p)
    pbytes = (b'\x00' * (k - len(pbytes))) + pbytes
    return pbytes[0:2] == b'\x00\x02'

def randnonzerobytes(k):
    return bytes(random.sample(range(1, 256), k))

def padPKCS15(s, n):
    if len(s) < 8:
        raise Exception('unexpected')
    k = (n.bit_length() + 7) // 8
    padding = randnonzerobytes(k - 3 - len(s))
    return b'\x00\x02' + padding + b'\x00' + s

def computeFirstS(e, n, B, c0, parityOracle):
    s = (n + 3*B - 1) // (3*B)
    while True:
        c = (c0 * pow(s, e, n)) % n
        if parityOracle(c):
            return (s, c)
        s += 1

def deducePlaintext(ciphertext, pub, parityOracle):
    e, n = pub
    k = (n.bit_length() + 7) // 8
    B = 2**(8*(k-2))
    c0 = challenge39.bytestonum(ciphertext)
    M = [(2*B, 3*B - 1)]
    (s, c) = computeFirstS(e, n, B, c0, parityOracle)
    print(s, c)
    # TODO(akalin): Deduce plaintext using parityOracle.
    return b''

if __name__ == '__main__':
    _, n = pub
    plaintext = padPKCS15(b'kick it, CC', n)
    ciphertext = challenge39.encryptbytes(pub, plaintext)
    plaintext2 = deducePlaintext(ciphertext, pub, parityOracle)
    if plaintext2 != plaintext:
        raise Exception(plaintext2 + b' != ' + plaintext)
