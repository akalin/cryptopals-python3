from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import getrandbits
import challenge18
import base64
import struct

key = get_random_bytes(16)
nonce = getrandbits(64)

def ciphertext_oracle():
    ecb_ciphertext = base64.b64decode(open('25.txt', 'r').read())
    ecb_key = b'YELLOW SUBMARINE'
    ecb_cipher = AES.new(ecb_key, AES.MODE_ECB)
    plaintext = ecb_cipher.decrypt(ecb_ciphertext)
    cipher = challenge18.CTR(AES.new(key, AES.MODE_ECB), nonce)
    return cipher.encrypt(plaintext)

def edit(ciphertext, offset, newtext):
    cipher = challenge18.CTR(AES.new(key, AES.MODE_ECB), nonce)
    cipher.encrypt(b'\x00' * offset)
    return ciphertext[0:offset] + cipher.encrypt(newtext)

ciphertext = ciphertext_oracle()
plaintext = edit(ciphertext, 0, ciphertext)
print(plaintext)
