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
    md4obj._do_round1(words, state, 4, 8)
    a2, b2, c2, d2 = state
    md4obj._do_round1(words, state, 8, 12)
    a3, b3, c3, d3 = state
    md4obj._do_round1(words, state, 12, 16)
    a4, b4, c4, d4 = state

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

    assert_bit(a3, 12, 1)
    assert_bit(a3, 13, 1)
    assert_bit(a3, 14, 1)
    assert_bit(a3, 16, 0)
    assert_bit(a3, 18, 0)
    assert_bit(a3, 19, 0)
    assert_bit(a3, 20, 0)
    assert_bit(a3, 22, nth_bit(b2, 22))
    assert_bit(a3, 21, 1)
    assert_bit(a3, 25, nth_bit(b2, 25))

    assert_bit(d3, 12, 1)
    assert_bit(d3, 13, 1)
    assert_bit(d3, 14, 1)
    assert_bit(d3, 16, 0)
    assert_bit(d3, 19, 0)
    assert_bit(d3, 20, 1)
    assert_bit(d3, 21, 1)
    assert_bit(d3, 22, 0)
    assert_bit(d3, 25, 1)
    assert_bit(d3, 29, nth_bit(a2, 29))

    assert_bit(c3, 16, 1)
    assert_bit(c3, 19, 0)
    assert_bit(c3, 20, 0)
    assert_bit(c3, 21, 0)
    assert_bit(c3, 22, 0)
    assert_bit(c3, 25, 0)
    assert_bit(c3, 29, 1)
    assert_bit(c3, 31, nth_bit(d3, 31))

    assert_bit(b3, 19, 0)
    assert_bit(b3, 20, 1)
    assert_bit(b3, 21, 1)
    assert_bit(b3, 22, nth_bit(c3, 22))
    assert_bit(b3, 25, 1)
    assert_bit(b3, 29, 0)
    assert_bit(b3, 31, 0)

    assert_bit(a4, 22, 0)
    assert_bit(a4, 25, 0)
    assert_bit(a4, 26, nth_bit(b3, 26))
    assert_bit(a4, 28, nth_bit(b3, 28))
    assert_bit(a4, 29, 1)
    assert_bit(a4, 31, 0)

    assert_bit(d4, 22, 0)
    assert_bit(d4, 25, 0)
    assert_bit(d4, 26, 1)
    assert_bit(d4, 28, 1)
    assert_bit(d4, 29, 0)
    assert_bit(d4, 31, 1)

    assert_bit(c4, 18, nth_bit(d4, 18))
    assert_bit(c4, 22, 1)
    assert_bit(c4, 25, 1)
    assert_bit(c4, 26, 0)
    assert_bit(c4, 28, 0)
    assert_bit(c4, 29, 0)

    assert_bit(b4, 18, 0)
    assert_bit(b4, 25, 1)
    assert_bit(b4, 26, 1)
    assert_bit(b4, 28, 1)
    assert_bit(b4, 29, 0)

def assert_collidable_round2(s):
    words = read_words_be(s)

    md4obj = md4.md4()
    state = list(md4obj._state)
    md4obj._do_round1(words, state)
    a4, b4, c4, d4 = state
    md4obj._do_round2(words, state, 0, 4)
    a5, b5, c5, d5 = state
    md4obj._do_round2(words, state, 4, 8)
    a6, b6, c6, d6 = state

    assert_bit(a5, 18, nth_bit(c4, 18))
    assert_bit(a5, 25, 1)
    assert_bit(a5, 26, 0)
    assert_bit(a5, 28, 1)
    assert_bit(a5, 31, 1)

    assert_bit(d5, 18, nth_bit(a5, 18))
    assert_bit(d5, 25, nth_bit(b4, 25))
    assert_bit(d5, 26, nth_bit(b4, 26))
    assert_bit(d5, 28, nth_bit(b4, 28))
    assert_bit(d5, 31, nth_bit(b4, 31))

    assert_bit(c5, 25, nth_bit(d5, 25))
    assert_bit(c5, 26, nth_bit(d5, 26))
    assert_bit(c5, 28, nth_bit(d5, 28))
    assert_bit(c5, 29, nth_bit(d5, 29))
    assert_bit(c5, 31, nth_bit(d5, 31))

    assert_bit(b5, 28, nth_bit(c5, 28))
    assert_bit(b5, 29, 1)
    assert_bit(b5, 31, 0)

    assert_bit(a6, 28, 1)
    assert_bit(a6, 31, 1)

    assert_bit(d6, 28, nth_bit(b5, 28))

    assert_bit(c6, 28, nth_bit(d6, 28))
    assert_bit(c6, 29, (nth_bit(d6, 29) + 1) % 2)
    assert_bit(c6, 31, (nth_bit(d6, 31) + 1) % 2)

def assert_collidable_round3(s):
    words = read_words_be(s)

    md4obj = md4.md4()
    state = list(md4obj._state)
    md4obj._do_round1(words, state)
    md4obj._do_round2(words, state)
    md4obj._do_round3(words, state, 0, 4)
    _, b9, _, _ = state
    md4obj._do_round3(words, state, 4, 8)
    a10, _, _, _ = state

    assert_bit(b9, 31, 1)
    assert_bit(a10, 31, 1)

def test_collision():
    assert_collidable_round1(collision_M1_str)
    assert_collidable_round1(collision_M2_str)

    assert_collidable_round2(collision_M1_str)
    assert_collidable_round2(collision_M2_str)

    assert_collidable_round3(collision_M1_str)
    assert_collidable_round3(collision_M2_str)

    assert_collision(collision_M1_str, collision_state1_str, collision_hash1_str)
    assert_collision(collision_M2_str, collision_state2_str, collision_hash2_str)

if __name__ == '__main__':
    test_md4()
    test_collision()
