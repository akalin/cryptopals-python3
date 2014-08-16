from Crypto.Cipher import AES
from Crypto.Random import random
import challenge11
import challenge18

import base64
import struct

key = challenge11.randbytes(16)
nonce = random.getrandbits(64)

def ciphertext_oracle():
    ecb_ciphertext = base64.b64decode(open('25.txt', 'r').read())
    ecb_key = b'YELLOW SUBMARINE'
    ecb_cipher = AES.new(ecb_key, AES.MODE_ECB)
    plaintext = ecb_cipher.decrypt(ecb_ciphertext)
    cipher = challenge18.CTR(AES.new(key, AES.MODE_ECB), nonce)
    return cipher.encrypt(plaintext)

print(ciphertext_oracle())
# TODO(akalin): Implement edit() and break the encryption with it.
