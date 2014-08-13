from Crypto.Cipher import AES
import base64
import challenge9
import challenge11

encodedSuffix = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
key = None

def encryption_oracle(s):
    global key
    if key is None:
        key = challenge11.randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    s = challenge9.padPKCS7(s + base64.b64decode(encodedSuffix), 16)
    return cipher.encrypt(s)
