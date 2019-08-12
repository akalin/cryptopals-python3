import binascii
import md4
import struct

def md4_hexdigest(m, msglen=None):
    md4obj = md4.md4()
    md4obj.update(m)
    return md4obj.hexdigest(msglen)

def assert_md4(s, expected_h):
    m = bytes(s, 'ascii')
    h = md4_hexdigest(m)
    if h != expected_h:
        raise Exception('expected {}, got {}'.format(expected_h, h))

def test_md4():
    # Taken from https://en.wikipedia.org/wiki/MD4 .
    assert_md4('', '31d6cfe0d16ae931b73c59d7e0c089c0')
    assert_md4('a', 'bde52cb31de33e46245e05fbdbd6fb24')
    assert_md4('abc', 'a448017aaf21d8525fc10ae87aa6729d')
    assert_md4('message digest', 'd9130a8164549fe818874806e1c7014b')
    assert_md4('abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9')
    assert_md4('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', '043f8582f241db351ce627e153e7f0e4')
    assert_md4('12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'e33b4ddc9c38f2199c3e7b164fcc0536')

# Taken from https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf .
collision_M1_str = '4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9'
collision_hash1_str = '4d7e6a1d efa93d2d de05b45d 864c429b'

def read_words_be(s):
    word_strs = s.split(' ')
    words = []
    for word_str in word_strs:
        word_bytes = binascii.unhexlify(word_str)
        (word,) = struct.unpack('>L', word_bytes)
        words.append(word)
    return words

def words_to_bytes_le(words):
    return b''.join([struct.pack('<L', word) for word in words])

def apply_collision_differential(words):
    words[1] = (words[1] + 2**31) % 2**32
    words[2] = (words[2] + 2**31 - 2**28) % 2**32
    words[12] = (words[12] - 2**16) % 2**32

def test_collision():
    words = read_words_be(collision_M1_str)
    collision_M1 = words_to_bytes_le(words)
    h = md4_hexdigest(collision_M1)
    expected_h = collision_hash1_str.replace(' ', '')
    if h != expected_h:
        raise Exception('expected {}, got {}'.format(expected_h, h))

    apply_collision_differential(words)
    collision_M1_prime = words_to_bytes_le(words)
    h = md4_hexdigest(collision_M1_prime)
    if h != expected_h:
        raise Exception('expected {}, got {}'.format(expected_h, h))

if __name__ == '__main__':
    test_md4()
    test_collision()
