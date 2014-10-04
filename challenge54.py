import challenge52
import challenge53

def constructCollisionTree(hashFn, blockLength, hashLength, k):
    leaves = [(i.to_bytes(hashLength, byteorder='little'),)
              for i in range(2**k)]

    initialStateMap = {leaves[i][0]:i for i in range(2**k)}

    collisionTree = [leaves]

    for i in range(1, k+1):
        prev_level = collisionTree[i-1]
        curr_level = [
            challenge53.findStatePrefixCollision(hashFn, prev_level[2*i][0], prev_level[2*i+1][0], blockLength) for i in range(2**(k-i))]
        collisionTree += [curr_level]

    return (initialStateMap, collisionTree)

def getSuffixFromCollisionTree(initialStateMap, collisionTree, iv):
    s = b''
    k = len(initialStateMap).bit_length() - 1

    i = initialStateMap[iv]
    for j in range(1, k+1):
        n = collisionTree[j][i//2]
        s += n[1 + (i%2)]
        i //= 2
    return s

if __name__ == '__main__':
    (initialStateMap, collisionTree) = constructCollisionTree(challenge52.badHash, challenge52.badHashBlockLength, challenge52.badHashHashLength, 5)
    for h in initialStateMap:
        s = getSuffixFromCollisionTree(initialStateMap, collisionTree, h)
        print(s, challenge52.badHash(s, h, pad=False))
