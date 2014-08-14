from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import challenge9
import challenge10
import challenge11
import challenge15

strings = [
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]

key = challenge11.randbytes(16)

def ciphertext_oracle():
    s = base64.b64decode(random.choice(strings))
    iv = challenge11.randbytes(16)
    cipher = challenge10.CBC(AES.new(key, AES.MODE_ECB), iv)
    return (iv, cipher.encrypt(challenge9.padPKCS7(s, 16)))

def padding_oracle(iv, s):
    cipher = challenge10.CBC(AES.new(key, AES.MODE_ECB), iv)
    paddedT = cipher.decrypt(s)
    try:
        t = challenge15.unpadPKCS7(paddedT)
    except ValueError:
        return False
    return True

(iv, s) = ciphertext_oracle()
print(padding_oracle(iv, s))
