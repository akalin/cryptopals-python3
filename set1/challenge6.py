def getHammingDistance(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])

x = b'this is a test'
y = b'wokka wokka!!!'
expectedD = 37
d = getHammingDistance(x, y)
if d != expectedD:
    raise Exception(encodedD + ' != ' + encodedExpectedD)
