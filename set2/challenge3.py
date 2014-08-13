from Crypto.Cipher import AES
from Crypto.Random import random
import challenge2

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
        cipher = challenge2.CBC(cipher, IV)
    s = randbytes(random.randint(5, 10)) + s + randbytes(random.randint(5, 10))
    return cipher.encrypt(s)
