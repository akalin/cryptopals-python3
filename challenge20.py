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
kl = len(key)
for s in encryptedStrings:
    print(strxor(s[:kl], key[:len(s)]) + s[kl:])
