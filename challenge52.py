from Crypto.Cipher import Blowfish
import struct
import util

def MerkleDamgard(f, processIV, blockLength, padMessage):
    def hashFn(m, iv, pad=True):
        H = processIV(iv)
        if pad:
            m = padMessage(m)
        elif len(m) % blockLength != 0:
            raise Exception('message of length {0} not a multiple of block length {1}'.format(len(m), blockLength))
        for block in (m[x:x+blockLength] for x in range(0, len(m), blockLength)):
            H = f(block, H)
        return H
    return hashFn

badHashHashLength = 2

def badHashF(messageBlock, state):
    cipher = Blowfish.new(state, Blowfish.MODE_ECB)
    newState = cipher.encrypt(messageBlock)[:badHashHashLength]
    return newState

def badHashProcessIV(iv):
    if len(iv) < badHashHashLength:
        return iv + (b'\x00' * (badHashHashLength - len(iv)))
    else:
        return iv[:badHashHashLength]

badHashBlockLength = 8

def badHashPadMessage(m):
    m += b'\x80'
    m += b'\x00' * ((-4 - (len(m) % badHashBlockLength)) % badHashBlockLength)
    m += struct.pack('>I', len(m))
    return m

badHash = MerkleDamgard(badHashF, badHashProcessIV, badHashBlockLength, badHashPadMessage)

def findPrefixCollision(hashFn, iv, blockLength, hashLength):
    hashToString = {}
    for s in (i.to_bytes(blockLength, byteorder='little') for i in range(2**(hashLength*8))):
        h = hashFn(s, iv, pad=False)
        if h in hashToString:
            return (h, s, hashToString[h])
        else:
            hashToString[h] = s
    raise Exception('unexpected')

def generateCollisions(hashFn, iv, blockLength, hashLength, n):
    state, s1, s2 = findPrefixCollision(hashFn, iv, blockLength, hashLength)
    collisions = [s1, s2]
    for i in range(n-1):
        state, s1, s2 = findPrefixCollision(hashFn, state, blockLength, hashLength)
        collisions = [x + s for x in collisions for s in [s1, s2]]
    return collisions

if __name__ == '__main__':
    for s in generateCollisions(badHash, b'', badHashBlockLength, badHashHashLength, 5):
        print(s, badHash(s, b''))
