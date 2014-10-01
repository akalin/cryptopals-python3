import challenge52

def findNBlockPrefixCollision(hashFn, iv, blockLength, n):
    prefix = b'\x00' * (blockLength * (n-1))
    prefixHash = hashFn(prefix, iv, pad=False)
    hashToLastBlock = {}
    for s in (i.to_bytes(blockLength, byteorder='little') for i in range(2**(blockLength*8))):
        h = hashFn(s, iv, pad=False)
        if h in hashToLastBlock:
            return (h, s, prefix + hashToLastBlock[h])

        h = hashFn(s, prefixHash, pad=False)
        hashToLastBlock[h] = s
    raise Exception('unexpected')

if __name__ == '__main__':
    h, s, nBlock = findNBlockPrefixCollision(challenge52.badHash, b'', challenge52.badHashBlockLength, 10)
    print(h, s, nBlock, challenge52.badHash(s, b'', pad=False), challenge52.badHash(nBlock, b'', pad=False))
