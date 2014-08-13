from Crypto.Cipher import AES
from Crypto.Random import random
import challenge9
import challenge10

def randbytes(k):
    return bytes(random.sample(range(0, 256), k))

def encryption_oracle(s):
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    if random.randint(0, 1) == 0:
        print('Encrypting with ECB')
    else:
        print('Encrypting with CBC')
        IV = randbytes(16)
        cipher = challenge10.CBC(cipher, IV)
    s = randbytes(random.randint(5, 10)) + s + randbytes(random.randint(5, 10))
    s = challenge9.padPKCS7(s, 16)
    return cipher.encrypt(s)

def detectMethod(encryption_oracle):
    s = bytes([0] * 47)
    t = encryption_oracle(s)
    if t[16:32] == t[32:48]:
        return 'ECB'
    return 'CBC'

print(detectMethod(encryption_oracle))
