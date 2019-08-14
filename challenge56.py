import base64
import binascii
import util

from Crypto.Cipher import ARC4

encoded_cookie = b'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'
cookie = base64.b64decode(encoded_cookie)

def encryption_oracle(b):
    key = util.randbytes(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(b + cookie)

def append_ciphertexts(b, S, C):
    for _ in range(S):
        C.append(encryption_oracle(b))

# Algorithm 3 from the paper.
def recover_ciphertext_byte(C, r):
    N = [0] * 256
    for c in C:
        N[c[r]] += 1
    return max(range(256), key=lambda i: N[i])

def recover_plaintext_byte(C, r, bias):
    cb = recover_ciphertext_byte(C, r)
    return cb ^ bias

def recover_plaintext_iter(ciphertext_length, iter_length, paddings, ciphertexts):
    plaintext = [0] * ciphertext_length

    for i, C in enumerate(ciphertexts):
        append_ciphertexts(paddings[i], iter_length, C)

    for i, C in enumerate(ciphertexts):
        b15 = recover_plaintext_byte(C, 15, 240)
        plaintext[15 - i] = b15
        # print('plaintext[{}] = {}'.format(15 - i, bytes([b15])))
        if i + ciphertext_length >= 32:
            b31 = recover_plaintext_byte(C, 31, 224)
            plaintext[31 - i] = b31
            # print('plaintext[{}] = {}'.format(31 - i, bytes([b31])))

    return len(ciphertexts[0]), plaintext

def recover_plaintext(iter_length, num_iters):
    ciphertext_length = len(encryption_oracle(b''))
    paddings = [bytes([0] * i) for i in range(16)]
    ciphertexts = [[] for padding in paddings]

    for i in range(num_iters):
        ciphertext_count, plaintext = recover_plaintext_iter(ciphertext_length, iter_length, paddings, ciphertexts)
        print('with {} ciphertexts, plaintext = {}'.format(ciphertext_count, bytes(plaintext)))

    return plaintext

plaintext = recover_plaintext(1 << 15, 1 << 5)
print('final plaintext = {}'.format(bytes(plaintext)))
