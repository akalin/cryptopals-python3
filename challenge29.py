from Crypto.Random import random
import challenge11
import challenge28
import struct

def padSHA1(s):
    l = len(s) * 8
    s += b'\x80'
    s += b'\x00' * ((56 - (len(s) % 64)) % 64)
    s += struct.pack('>Q', l)
    return s

keylen = random.randint(0, 100)
key = challenge11.randbytes(keylen)

def validate(message, digest):
    return challenge28.authSHA1(key, message) == digest

message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
messageDigest = challenge28.authSHA1(key, message)

def forgeHash(keylen, message, digest, suffix):
    # TODO(akalin): Implement.
    return (message + suffix, b'')

def forgeValidatingHash(maxkeylen, message, digest, suffix):
    for i in range(maxkeylen):
        (forgedMessage, forgedDigest) = forgeHash(i, message, digest, suffix)
        if validate(forgedMessage, forgedDigest):
            return(forgedMessage, forgedDigest)
    raise Exception('unexpected')

print(forgeValidatingHash(100, message, messageDigest, b';admin=true'))
