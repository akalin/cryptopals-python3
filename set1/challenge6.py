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

for i in range(2, 41):
    key = breakRepeatingKeyXor(x, i)
    y = challenge5.encodeRepeatingKeyXor(x, key)
    print(i, key, y)
