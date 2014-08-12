import binascii
import challenge3

def decodeLines(filename):
    f = open(filename, 'r')
    for line in f:
        if line[-1] == '\n':
            line = line[:-1]
        s = binascii.unhexlify(line)
        yield s

def findSingleByteXOR(lines):
    brokenLines = [challenge3.breakSingleByteXOR(l) for l in lines]
    def score(i):
        return challenge3.score(brokenLines[i])
    maxI = max(range(len(brokenLines)), key=score)
    return (maxI+1, brokenLines[maxI])

print(findSingleByteXOR(decodeLines('4.txt')))
