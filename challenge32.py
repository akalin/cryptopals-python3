import binascii
import challenge31
import sys

if __name__ == '__main__':
    file = sys.argv[1]
    knownBytes = b''
    DELAY = 0.005
    for i in range(20):
        knownBytes = challenge31.guessNextByte(file, knownBytes, DELAY)
        print(binascii.hexlify(knownBytes))
    print(binascii.hexlify(knownBytes))
    if not challenge31.isValidSignature(file, binascii.hexlify(knownBytes).decode('ascii'))[0]:
        raise Exception('unexpected')
