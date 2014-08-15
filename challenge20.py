from Crypto.Util.strxor import strxor
import base64
import challenge3
import challenge19
import itertools

strings = [base64.b64decode(x) for x in open('20.txt', 'r').read().split('\n')]
strings = strings[:-1]

encryptedStrings = [challenge19.encryptString(s) for s in strings]

def breakSameKey(strings):
    transposedStrings = list(zip(*strings))
    key = [challenge3.breakSingleByteXOR(bytes(x))[0] for x in transposedStrings]
    return bytes(key)

key = breakSameKey(encryptedStrings)
key = bytes([encryptedStrings[0][0] ^ ord('I')]) + key[1:]
key = challenge19.extendKey(key, encryptedStrings[13], b'-M ')
key = challenge19.extendKey(key, encryptedStrings[16], b'ime ')
key = challenge19.extendKey(key, encryptedStrings[1], b'htnin')
key = challenge19.extendKey(key, encryptedStrings[2], b'y')
key = challenge19.extendKey(key, encryptedStrings[6], b'ty')
key = challenge19.extendKey(key, encryptedStrings[0], b'i')
key = challenge19.extendKey(key, encryptedStrings[3], b'n up')
kl = len(key)
for s in encryptedStrings:
    print(strxor(s[:kl], key[:len(s)]) + s[kl:])
