from Crypto.Cipher import AES

import util

def CBC_MAC(key, iv, p):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    c = cipher.encrypt(util.padPKCS7(p, 16))
    return c[-16:]

key = util.randbytes(16)

if __name__ == '__main__':
    print(CBC_MAC(key, b'\x00' * 16, b'plaintext'))
