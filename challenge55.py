import binascii
import md4
import struct
import util

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

def write_words_be(words):
    b = struct.pack('>16I', *words)
    s = binascii.hexlify(b).decode('ascii')
    k = 8
    return ' '.join(s[i:i+k] for i in range(0, len(s), k))

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

    a0, b0, c0, d0 = md4.INITIAL_STATE
    states = md4.do_round1(words, md4.INITIAL_STATE)
    a1, b1, c1, d1 = states[0]
    a2, b2, c2, d2 = states[1]
    a3, b3, c3, d3 = states[2]
    a4, b4, c4, d4 = states[3]

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

def assert_collidable_round2_a5(s, loose=False):
    words = read_words_be(s)

    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    a4, b4, c4, d4 = round1_states[-1]

    round2_states = md4.do_round2(words, round1_states[-1])
    a5, b5, c5, d5 = round2_states[0]

    assert_bit(a5, 18, nth_bit(c4, 18))
    assert_bit(a5, 25, 1)
    assert_bit(a5, 26, 0)
    assert_bit(a5, 28, 1)
    assert_bit(a5, 31, 1)

def assert_collidable_round2_d5(s, loose=False):
    words = read_words_be(s)

    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    a4, b4, c4, d4 = round1_states[-1]

    round2_states = md4.do_round2(words, round1_states[-1])
    a5, b5, c5, d5 = round2_states[0]

    assert_bit(d5, 18, nth_bit(a5, 18))
    assert_bit(d5, 25, nth_bit(b4, 25))
    assert_bit(d5, 26, nth_bit(b4, 26))
    assert_bit(d5, 28, nth_bit(b4, 28))

def assert_collidable_round2(s):
    words = read_words_be(s)

    assert_collidable_round2_a5(s)
    assert_collidable_round2_d5(s)

    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    a4, b4, c4, d4 = round1_states[-1]

    round2_states = md4.do_round2(words, round1_states[-1])
    a5, b5, c5, d5 = round2_states[0]
    a6, b6, c6, d6 = round2_states[1]

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

    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    round2_states = md4.do_round2(words, round1_states[-1])
    round3_states = md4.do_round3(words, round2_states[-1])
    _, b9, _, _ = round3_states[0]
    a10, _, _, _ = round3_states[1]

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

def set_nth_bit(x, n, b):
    return (x & ~(1 << n)) | (b << n)

def rrot(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xffffffff)

def do_single_step_mod(words):
    a0, b0, c0, d0 = md4.INITIAL_STATE
    states = md4.do_round1(words, md4.INITIAL_STATE)
    a1, b1, c1, d1 = states[0]
    a2, b2, c2, d2 = states[1]
    a3, b3, c3, d3 = states[2]
    a4, b4, c4, d4 = states[3]

    a1 = set_nth_bit(a1, 6, nth_bit(b0, 6))

    d1 = set_nth_bit(d1, 6, 0)
    d1 = set_nth_bit(d1, 7, nth_bit(a1, 7))
    d1 = set_nth_bit(d1, 10, nth_bit(a1, 10))

    c1 = set_nth_bit(c1, 6, 1)
    c1 = set_nth_bit(c1, 7, 1)
    c1 = set_nth_bit(c1, 10, 0)
    c1 = set_nth_bit(c1, 25, nth_bit(d1, 25))

    b1 = set_nth_bit(b1, 6, 1)
    b1 = set_nth_bit(b1, 7, 0)
    b1 = set_nth_bit(b1, 10, 0)
    b1 = set_nth_bit(b1, 25, 0)

    a2 = set_nth_bit(a2, 7, 1)
    a2 = set_nth_bit(a2, 10, 1)
    a2 = set_nth_bit(a2, 25, 0)
    a2 = set_nth_bit(a2, 13, nth_bit(b1, 13))

    d2 = set_nth_bit(d2, 13, 0)
    d2 = set_nth_bit(d2, 18, nth_bit(a2, 18))
    d2 = set_nth_bit(d2, 19, nth_bit(a2, 19))
    d2 = set_nth_bit(d2, 20, nth_bit(a2, 20))
    d2 = set_nth_bit(d2, 21, nth_bit(a2, 21))
    d2 = set_nth_bit(d2, 25, 1)

    c2 = set_nth_bit(c2, 12, nth_bit(d2, 12))
    c2 = set_nth_bit(c2, 13, 0)
    c2 = set_nth_bit(c2, 14, nth_bit(d2, 14))
    c2 = set_nth_bit(c2, 18, 0)
    c2 = set_nth_bit(c2, 19, 0)
    c2 = set_nth_bit(c2, 20, 1)
    c2 = set_nth_bit(c2, 21, 0)

    b2 = set_nth_bit(b2, 12, 1)
    b2 = set_nth_bit(b2, 13, 1)
    b2 = set_nth_bit(b2, 14, 0)
    b2 = set_nth_bit(b2, 16, nth_bit(c2, 16))
    b2 = set_nth_bit(b2, 18, 0)
    b2 = set_nth_bit(b2, 19, 0)
    b2 = set_nth_bit(b2, 20, 0)
    b2 = set_nth_bit(b2, 21, 0)

    a3 = set_nth_bit(a3, 12, 1)
    a3 = set_nth_bit(a3, 13, 1)
    a3 = set_nth_bit(a3, 14, 1)
    a3 = set_nth_bit(a3, 16, 0)
    a3 = set_nth_bit(a3, 18, 0)
    a3 = set_nth_bit(a3, 19, 0)
    a3 = set_nth_bit(a3, 20, 0)
    a3 = set_nth_bit(a3, 22, nth_bit(b2, 22))
    a3 = set_nth_bit(a3, 21, 1)
    a3 = set_nth_bit(a3, 25, nth_bit(b2, 25))

    d3 = set_nth_bit(d3, 12, 1)
    d3 = set_nth_bit(d3, 13, 1)
    d3 = set_nth_bit(d3, 14, 1)
    d3 = set_nth_bit(d3, 16, 0)
    d3 = set_nth_bit(d3, 19, 0)
    d3 = set_nth_bit(d3, 20, 1)
    d3 = set_nth_bit(d3, 21, 1)
    d3 = set_nth_bit(d3, 22, 0)
    d3 = set_nth_bit(d3, 25, 1)
    d3 = set_nth_bit(d3, 29, nth_bit(a2, 29))

    c3 = set_nth_bit(c3, 16, 1)
    c3 = set_nth_bit(c3, 19, 0)
    c3 = set_nth_bit(c3, 20, 0)
    c3 = set_nth_bit(c3, 21, 0)
    c3 = set_nth_bit(c3, 22, 0)
    c3 = set_nth_bit(c3, 25, 0)
    c3 = set_nth_bit(c3, 29, 1)
    c3 = set_nth_bit(c3, 31, nth_bit(d3, 31))

    b3 = set_nth_bit(b3, 19, 0)
    b3 = set_nth_bit(b3, 20, 1)
    b3 = set_nth_bit(b3, 21, 1)
    b3 = set_nth_bit(b3, 22, nth_bit(c3, 22))
    b3 = set_nth_bit(b3, 25, 1)
    b3 = set_nth_bit(b3, 29, 0)
    b3 = set_nth_bit(b3, 31, 0)

    a4 = set_nth_bit(a4, 22, 0)
    a4 = set_nth_bit(a4, 25, 0)
    a4 = set_nth_bit(a4, 26, nth_bit(b3, 26))
    a4 = set_nth_bit(a4, 28, nth_bit(b3, 28))
    a4 = set_nth_bit(a4, 29, 1)
    a4 = set_nth_bit(a4, 31, 0)

    d4 = set_nth_bit(d4, 22, 0)
    d4 = set_nth_bit(d4, 25, 0)
    d4 = set_nth_bit(d4, 26, 1)
    d4 = set_nth_bit(d4, 28, 1)
    d4 = set_nth_bit(d4, 29, 0)
    d4 = set_nth_bit(d4, 31, 1)

    c4 = set_nth_bit(c4, 18, nth_bit(d4, 18))
    c4 = set_nth_bit(c4, 22, 1)
    c4 = set_nth_bit(c4, 25, 1)
    c4 = set_nth_bit(c4, 26, 0)
    c4 = set_nth_bit(c4, 28, 0)
    c4 = set_nth_bit(c4, 29, 0)

    b4 = set_nth_bit(b4, 18, 0)
    b4 = set_nth_bit(b4, 25, 1)
    b4 = set_nth_bit(b4, 26, 1)
    b4 = set_nth_bit(b4, 28, 1)
    b4 = set_nth_bit(b4, 29, 0)

    words_new = list(words)

    words_new[0] = (rrot(a1, 3) - a0 - md4.F(b0, c0, d0)) % 2**32
    words_new[1] = (rrot(d1, 7) - d0 - md4.F(a1, b0, c0)) % 2**32
    words_new[2] = (rrot(c1, 11) - c0 - md4.F(d1, a1, b0)) % 2**32
    words_new[3] = (rrot(b1, 19) - b0 - md4.F(c1, d1, a1)) % 2**32

    words_new[4] = (rrot(a2, 3) - a1 - md4.F(b1, c1, d1)) % 2**32
    words_new[5] = (rrot(d2, 7) - d1 - md4.F(a2, b1, c1)) % 2**32
    words_new[6] = (rrot(c2, 11) - c1 - md4.F(d2, a2, b1)) % 2**32
    words_new[7] = (rrot(b2, 19) - b1 - md4.F(c2, d2, a2)) % 2**32

    words_new[8] = (rrot(a3, 3) - a2 - md4.F(b2, c2, d2)) % 2**32
    words_new[9] = (rrot(d3, 7) - d2 - md4.F(a3, b2, c2)) % 2**32
    words_new[10] = (rrot(c3, 11) - c2 - md4.F(d3, a3, b2)) % 2**32
    words_new[11] = (rrot(b3, 19) - b2 - md4.F(c3, d3, a3)) % 2**32

    words_new[12] = (rrot(a4, 3) - a3 - md4.F(b3, c3, d3)) % 2**32
    words_new[13] = (rrot(d4, 7) - d3 - md4.F(a4, b3, c3)) % 2**32
    words_new[14] = (rrot(c4, 11) - c3 - md4.F(d4, a4, b3)) % 2**32
    words_new[15] = (rrot(b4, 19) - b3 - md4.F(c4, d4, a4)) % 2**32

    return words_new

def lrot(x, n):
    return rrot(x, 32 - n)

def do_a5_mod(words, a5i, b):
    s = write_words_be(words)
    assert_collidable_round1(s)

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    round2_states = md4.do_round2(words, round1_states[-1])
    a5, b5, c5, d5 = round2_states[0]

    if nth_bit(a5, a5i) == b:
        return words

    a0, b0, c0, d0 = md4.INITIAL_STATE
    a1, b1, c1, d1 = round1_states[0]
    a2, b2, c2, d2 = round1_states[1]
    a3, b3, c3, d3 = round1_states[2]
    a4, b4, c4, d4 = round1_states[3]

    a5_new = set_nth_bit(a5, a5i, b)

    words_new = list(words)
    words_new[0] = (rrot(a5_new, 3) - a4 - md4.G(b4, c4, d4) - 0x5a827999) % 2**32

    a1_new = lrot((a0 + md4.F(b0, c0, d0) + words_new[0]) % 2**32, 3)

    words_new[1] = (rrot(d1, 7) - d0 - md4.F(a1_new, b0, c0)) % 2**32
    words_new[2] = (rrot(c1, 11) - c0 - md4.F(d1, a1_new, b0)) % 2**32
    words_new[3] = (rrot(b1, 19) - b0 - md4.F(c1, d1, a1_new)) % 2**32
    words_new[4] = (rrot(a2, 3) - a1_new - md4.F(b1, c1, d1)) % 2**32

    s = write_words_be(words_new)
    assert_collidable_round1(s)

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    round2_states = md4.do_round2(words, round1_states[-1])
    a5, b5, c5, d5 = round2_states[0]

    assert_bit(a5, a5i, b)

    return words_new

def do_d5_mod(words, initial_state, round1_states, round2_states, d5i, b):
    s = write_words_be(words)
    assert_collidable_round1(s)
    assert_collidable_round2_a5(s)

    a0, b0, c0, d0 = md4.INITIAL_STATE
    a1, b1, c1, d1 = round1_states[0]
    a2, b2, c2, d2 = round1_states[1]
    a3, b3, c3, d3 = round1_states[2]
    a4, b4, c4, d4 = round1_states[3]
    a5, b5, c5, d5 = round2_states[0]
    a6, b6, c6, d6 = round2_states[1]

    if nth_bit(d5, d5i) == b:
        return words, round1_states, round2_states

    d5_new = set_nth_bit(d5, i, expected_b)

    words_new = list(words)
    words_new[4] = (rrot(d5_new, 5) - d4 - md4.G(a5, b4, c4) - 0x5a827999) % 2**32

    a2_new = lrot((a1 + md4.F(b1, c1, d1) + words_new[4]) % 2**32, 3)

    words_new[5] = (rrot(d2, 7) - d1 - md4.F(a2_new, b1, c1)) % 2**32
    words_new[6] = (rrot(c2, 11) - c1 - md4.F(d2, a2_new, b1)) % 2**32
    words_new[7] = (rrot(b2, 19) - b1 - md4.F(c2, d2, a2_new)) % 2**32
    words_new[8] = (rrot(a3, 3) - a2_new - md4.F(b2, c2, d2)) % 2**32

    round1_states_new = list(round1_states)
    round1_states_new[1] = list(round1_states_new[1])
    round1_states_new[1][0] = a2_new

    round2_states_new = list(round2_states)
    round2_states_new[0] = list(round2_states_new[0])
    round2_states_new[0][3] = d5_new

    s = write_words_be(words)
    assert_collidable_round1(s)
    assert_collidable_round2_a5(s)

    return words_new, round1_states_new, round2_states_new

def do_multi_step_mod(words):
    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    _, _, _, c4 = round1_states[-1]

    words = do_a5_mod(words, 18, nth_bit(c4, 18))
    words = do_a5_mod(words, 25, 1)
    words = do_a5_mod(words, 26, 0)
    words = do_a5_mod(words, 28, 1)
    words = do_a5_mod(words, 31, 1)

    s = write_words_be(words)
    assert_collidable_round1(s)
    assert_collidable_round2_a5(s)

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    _, _, b4, _ = round1_states[-1]
    round2_states = md4.do_round2(words, round1_states[-1])
    a5, _, _, _ = round2_states[0]
    words, round1_states, round2_states = do_d5_mod(words, initial_state, round1_states, round2_states, 18, nth_bit(a5, 18))

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    _, _, b4, _ = round1_states[-1]
    words, round1_states, round2_states = do_d5_mod(words, initial_state, round1_states, round2_states, 25, nth_bit(b4, 25))

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    _, _, b4, _ = round1_states[-1]
    words, round1_states, round2_states = do_d5_mod(words, initial_state, round1_states, round2_states, 26, nth_bit(b4, 26))

    initial_state = md4.INITIAL_STATE
    round1_states = md4.do_round1(words, md4.INITIAL_STATE)
    _, _, b4, _ = round1_states[-1]
    words, round1_states, round2_states = do_d5_mod(words, initial_state, round1_states, round2_states, 28, nth_bit(b4, 28))

    s = write_words_be(words)
    assert_collidable_round1(s)
    assert_collidable_round2_a5(s)
    assert_collidable_round2_d5(s)

    return words

def tweak_and_test(words, verbose=False):
    if verbose:
        print('s before tweaking = {}'.format(write_words_be(words)))

    words = do_single_step_mod(words)

    s = write_words_be(words)
    assert_collidable_round1(s)

    if verbose:
        print('s after tweaking for round 1 = {}'.format(s))

    words = do_multi_step_mod(words)

    s = write_words_be(words)
    if verbose:
        print('s after tweaking for round 2 = {}'.format(s))

    apply_collision_differential(words)
    s_prime = write_words_be(words)

    if verbose:
        print('s\' = {}'.format(s_prime))

    h = md4_hexdigest(bytes(s, 'ascii'))
    h_prime = md4_hexdigest(bytes(s_prime, 'ascii'))
    if h == h_prime:
        print('md4 {} == {}'.format(h, h_prime))
        return (s, s_prime)
    else:
        if verbose:
            print('md4 {} != {}'.format(h, h_prime))
        return None

def find_collision(n):
    for i in range(n):
        if i % 1000 == 0:
            print('Iteration {}/{}'.format(i + 1, n))
        b = util.randbytes(64)
        words = struct.unpack('>16I', b)
        words = list(words)
        result = tweak_and_test(words)
        if result:
            break

if __name__ == '__main__':
    test_md4()
    test_collision()

    words = [0] * 16
    tweak_and_test(words, True)

#    find_collision(10000)
