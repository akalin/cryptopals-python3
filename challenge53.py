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

def makeExpandablePrefix(hashFn, iv, blockLength, k):
    blocks = []
    state = iv
    for i in range(k):
        state, s, nBlock = findNBlockPrefixCollision(hashFn, state, blockLength, 2**(k-1-i)+1)
        blocks += [[s, nBlock]]
    return state, blocks

def makeExpandedPrefix(blockSize, blocks, k, l):
    m = b''
    for i in range(len(blocks)):
        block = blocks[i]
        if len(m) // blockSize + len(block[1]) // blockSize + (len(blocks) - i - 1) <= l:
            nextSegment = block[1]
        else:
            nextSegment = block[0]
        m += nextSegment
    if len(m) // blockSize != l:
        raise Exception('unexpected')
    return m

if __name__ == '__main__':
    k = 5
    state, blocks = makeExpandablePrefix(challenge52.badHash, b'', challenge52.badHashBlockLength, k)
    for i in range(k, k + 2**k - 1):
        m = makeExpandedPrefix(challenge52.badHashBlockLength, blocks, k, i)
        mState = challenge52.badHash(m, b'', pad=False)
        print(m, mState)
        if state != mState:
            raise Exception(state + b' != ' + mState)
