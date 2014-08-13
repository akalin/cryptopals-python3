import base64
import challenge3
import challenge5
import itertools

def getHammingDistance(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])

x = b'this is a test'
y = b'wokka wokka!!!'
expectedD = 37
d = getHammingDistance(x, y)
if d != expectedD:
    raise Exception(encodedD + ' != ' + encodedExpectedD)

x = base64.b64decode(open('6.txt', 'r').read())

def breakRepeatingKeyXor(x, k):
    blocks = [x[i:i+k] for i in range(0, len(x), k)]
    transposedBlocks = list(itertools.zip_longest(*blocks, fillvalue=0))
    key = [challenge3.breakSingleByteXOR(bytes(x))[0] for x in transposedBlocks]
    return bytes(key)

def normalizedEditDistance(x, k):
    blocks = [x[i:i+k] for i in range(0, len(x), k)][0:4]
    pairs = list(itertools.combinations(blocks, 2))
    scores = [getHammingDistance(p[0], p[1])/float(k) for p in pairs][0:6]
    return sum(scores) / len(scores)

k = min(range(2, 41), key=lambda k: normalizedEditDistance(x, k))

key = breakRepeatingKeyXor(x, k)
y = challenge5.encodeRepeatingKeyXor(x, key)
print(key, y)
