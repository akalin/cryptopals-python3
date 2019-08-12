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
collision_state1_str = '5f5c1a0d 71b36046 1b5435da 9b0d807a'
collision_hash1_str = '4d7e6a1d efa93d2d de05b45d 864c429b'

collision_M2_str = '4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69'
# Padded last word with 0 (from string in the paper).
collision_state2_str = 'e0f76122 c429c56c ebb5e256 0b809793'
collision_hash2_str = 'c6f3b3fe 1f4833e0 697340fb 214fb9ea'

def read_words_be(s):
    b = binascii.unhexlify(s.replace(' ', ''))
    words = struct.unpack('>16I', b)
    return list(words)

def words_to_bytes_le(words):
    return struct.pack('<16I', *words)

def assert_md4_state(b, expected_state_str, expected_hash_str):
    md4obj = md4.md4()
    md4obj.update(b)

    expected_s = expected_state_str.replace(' ', '')
    s = binascii.hexlify(md4obj.state_be()).decode('ascii')
    if s != expected_s:
        raise Exception('expected {}, got {}'.format(expected_s, s))

    expected_h = expected_hash_str.replace(' ', '')
    h = md4obj.hexdigest()
    if h != expected_h:
        raise Exception('expected {}, got {}'.format(expected_h, h))

def apply_collision_differential(words):
    words[1] = (words[1] + 2**31) % 2**32
    words[2] = (words[2] + 2**31 - 2**28) % 2**32
    words[12] = (words[12] - 2**16) % 2**32

def assert_collision(s, expected_state_str, expected_hash_str):
    words = read_words_be(s)
    b = words_to_bytes_le(words)

    assert_md4_state(b, expected_state_str, expected_hash_str)

    apply_collision_differential(words)
    b_prime = words_to_bytes_le(words)
    assert_md4_state(b_prime, expected_state_str, expected_hash_str)

def nth_bit(x, n):
    return (x & (1 << n)) >> n

def assert_bit(x, n, expected_b):
    b = nth_bit(x, n)
    if b != expected_b:
        raise Exception('expected {}, got {}'.format(expected_b, b))

def assert_collidable_round1(s):
    words = read_words_be(s)

    md4obj = md4.md4()
    state = list(md4obj._state)
    a0, b0, c0, d0 = state
    md4obj._do_round1(words, state, 0, 4)
    a1, b1, c1, d1 = state

    assert_bit(a1, 6, nth_bit(b0, 6))

    assert_bit(d1, 6, 0)
    assert_bit(d1, 7, nth_bit(a1, 7))
    assert_bit(d1, 10, nth_bit(a1, 10))

    assert_bit(c1, 6, 1)
    assert_bit(c1, 7, 1)
    assert_bit(c1, 10, 0)
    assert_bit(c1, 25, nth_bit(d1, 25))

    assert_bit(b1, 6, 1)
    assert_bit(b1, 7, 0)
    assert_bit(b1, 10, 0)
    assert_bit(b1, 25, 0)

def assert_collidable_round2(s):
    words = read_words_be(s)

    md4obj = md4.md4()
    state = list(md4obj._state)
    md4obj._do_round1(words, state, 0, 4)
    a1, b1, c1, d1 = state
    md4obj._do_round1(words, state, 4, 8)
    a2, b2, c2, d2 = state

    assert_bit(a2, 7, 1)
    assert_bit(a2, 10, 1)
    assert_bit(a2, 25, 0)
    assert_bit(a2, 13, nth_bit(b1, 13))

    assert_bit(d2, 13, 0)
    assert_bit(d2, 18, nth_bit(a2, 18))
    assert_bit(d2, 19, nth_bit(a2, 19))
    assert_bit(d2, 20, nth_bit(a2, 20))
    assert_bit(d2, 21, nth_bit(a2, 21))
    assert_bit(d2, 25, 1)

    assert_bit(c2, 12, nth_bit(d2, 12))
    assert_bit(c2, 13, 0)
    assert_bit(c2, 14, nth_bit(d2, 14))
    assert_bit(c2, 18, 0)
    assert_bit(c2, 19, 0)
    assert_bit(c2, 20, 1)
    assert_bit(c2, 21, 0)

    assert_bit(b2, 12, 1)
    assert_bit(b2, 13, 1)
    assert_bit(b2, 14, 0)
    assert_bit(b2, 16, nth_bit(c2, 16))
    assert_bit(b2, 18, 0)
    assert_bit(b2, 19, 0)
    assert_bit(b2, 20, 0)
    assert_bit(b2, 21, 0)

def test_collision():
    assert_collidable_round1(collision_M1_str)
    assert_collidable_round1(collision_M2_str)

    assert_collidable_round2(collision_M1_str)
    assert_collidable_round2(collision_M2_str)

    assert_collision(collision_M1_str, collision_state1_str, collision_hash1_str)
    assert_collision(collision_M2_str, collision_state2_str, collision_hash2_str)

if __name__ == '__main__':
    test_md4()
    test_collision()
