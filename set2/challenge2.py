import base64
from Crypto.Cipher import AES

class CBC:
    def __init__(self, ECB, IV):
        self._ECB = ECB
        self._IV = IV
        self._blocksize = 16

    def encrypt(self, plaintext):
        return plaintext

    def decrypt(self, ciphertext):
        return ciphertext

x = base64.b64decode(open('10.txt', 'r').read())

key = b'YELLOW SUBMARINE'
cipher = CBC(AES.new(key, AES.MODE_ECB), bytes([0] * 16))
y = cipher.decrypt(x)
print(y)
z = cipher.encrypt(y)
if x != z:
    raise Exception(x + b' != ' + z)
