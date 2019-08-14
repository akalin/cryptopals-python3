import base64
import util

from Crypto.Cipher import ARC4

encoded_cookie = b'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'
cookie = base64.b64decode(encoded_cookie)

def encryption_oracle(b):
    key = util.randbytes(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(b + cookie)

print(encryption_oracle(b''))
