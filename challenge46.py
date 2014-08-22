import base64
import challenge39

pub, priv = challenge39.genKey(1024)

def parityOracle(c):
    p = challenge39.decryptnum(priv, c)
    return p % 2

def deducePlaintext(ciphertext, pub, parityOracle):
    (_, n) = pub
    low = 0
    high = 1
    denom = 1
    # TODO(akalin): Use the parity oracle to deduce the plaintext.
    return b''

if __name__ == '__main__':
    encodedPlaintext = b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
    plaintext = base64.b64decode(encodedPlaintext)
    ciphertext = challenge39.encryptbytes(pub, plaintext)
    plaintext2 = deducePlaintext(ciphertext, pub, parityOracle)
    if plaintext2 != plaintext:
        raise Exception(b'Invalid plaintext ' + plaintext2)
