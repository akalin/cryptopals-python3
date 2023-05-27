import base64
import binascii

from Cryptodome.Cipher import ARC4
from Cryptodome.Random import get_random_bytes

encoded_cookie = b'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'
cookie = base64.b64decode(encoded_cookie)

def encryption_oracle(b):
    key = get_random_bytes(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(b + cookie)

def add_to_pos_distributions(b, iter_length, pos_distributions):
    for _ in range(iter_length):
        ciphertext = encryption_oracle(b)
        for pos, distribution in pos_distributions.items():
            distribution[ciphertext[pos]] += 1

char_range = range(0, 256)

def recover_plaintext_byte(distribution, bias):
    return max(char_range, key=lambda i: distribution[i ^ bias])

def recover_plaintext_iter(ciphertext_length, iter_length, paddings, pos_distribution_groups):
    plaintext = [0] * ciphertext_length

    for i, pos_distributions in enumerate(pos_distribution_groups):
        add_to_pos_distributions(paddings[i], iter_length, pos_distributions)

    for i, pos_distributions in enumerate(pos_distribution_groups):
        b15 = recover_plaintext_byte(pos_distributions[15], 240)
        plaintext[15 - i] = b15
        # print('plaintext[{}] = {}'.format(15 - i, bytes([b15])))
        if i + ciphertext_length >= 32:
            b31 = recover_plaintext_byte(pos_distributions[31], 224)
            plaintext[31 - i] = b31
            # print('plaintext[{}] = {}'.format(31 - i, bytes([b31])))

    return plaintext

def recover_plaintext(iter_length, num_iters):
    ciphertext_length = len(encryption_oracle(b''))
    paddings = [bytes([0] * i) for i in range(16)]

    # Each entry in pos_distribution_groups (named pos_distributions)
    # is a map from a ciphertext character position (15 or 31) to a
    # histogram of ciphertext character frequencies.
    pos_distribution_groups = []
    for i, padding in enumerate(paddings):
        pos_distributions = {15: [0] * 256}
        if i + ciphertext_length >= 32:
            pos_distributions[31] = [0] * 256
        pos_distribution_groups.append(pos_distributions)

    for i in range(num_iters):
        plaintext = recover_plaintext_iter(ciphertext_length, iter_length, paddings, pos_distribution_groups)
        ciphertexts_per_pair = sum(pos_distribution_groups[0][15])
        print('with {} ciphertexts per 2 positions, plaintext = {}'.format(ciphertexts_per_pair, bytes(plaintext)))

    return plaintext

plaintext = recover_plaintext(1 << 14, 1 << 18)
print('final plaintext = {}'.format(bytes(plaintext)))
