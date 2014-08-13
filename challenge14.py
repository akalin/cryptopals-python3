from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import challenge9
import challenge11
import challenge12

key = None
prefix = None

def encryption_oracle(s):
    global key
    global prefix
    if key is None:
        key = challenge11.randbytes(16)
    if prefix is None:
        # TODO(akalin): Extend to arbitrary sizes.
        randcount = random.randint(0, 16)
        prefix = challenge11.randbytes(randcount)
    cipher = AES.new(key, AES.MODE_ECB)
    s = challenge9.padPKCS7(prefix + s + base64.b64decode(challenge12.encodedSuffix), 16)
    return cipher.encrypt(s)

def findPrefixSize(encryption_oracle, blocksize):
    def has_equal_block(blocks):
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                return True
        return False

    for i in range(blocksize):
        s = bytes([0] * (2*blocksize + i))
        t = encryption_oracle(s)
        blocks = [t[i:i+blocksize] for i in range(0, len(t), blocksize)]
        if has_equal_block(blocks):
            return blocksize - i

    raise Exception('Not using ECB')

def findNextByte(encryption_oracle, blocksize, prefixsize, knownBytes):
    k1 = blocksize - prefixsize
    k2 = blocksize - (len(knownBytes) % blocksize) - 1
    s = bytes([0] * (k1 + k2))
    d = {}
    for i in range(256):
        t = encryption_oracle(s + knownBytes + bytes([i]))
        d[t[k1:k1+k2 + len(knownBytes) + 1]] = i
    t = encryption_oracle(s)
    u = t[k1:k1+k2 + len(knownBytes) + 1]
    if u in d:
        return d[u]
    return None

blocksize = challenge12.findBlockSize(encryption_oracle)
prefixsize = findPrefixSize(encryption_oracle, blocksize)
s = b''
while True:
    b = findNextByte(encryption_oracle, blocksize, prefixsize, s)
    if b is None:
        break
    s += bytes([b])
print(s)
