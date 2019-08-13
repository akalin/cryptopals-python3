#=========================================================================
#imports
#=========================================================================
#core
from binascii import hexlify
import struct
from warnings import warn
from util import lrot32, rrot32
#local
__all__ = [ "md4" ]
#=========================================================================
#utils
#=========================================================================
def F(x,y,z):
    return (x&y) | ((~x) & z)

def G(x,y,z):
    return (x&y) | (x&z) | (y&z)

##def H(x,y,z):
##    return x ^ y ^ z

MASK_32 = 2**32-1

INITIAL_STATE = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
]

def do_round1(X, s0=INITIAL_STATE):

    #round 1 - F function - (x&y)|(~x & z)

    s1 = [0, 0, 0, 0]

    s1[0] = lrot32((s0[0] + F(s0[1], s0[2], s0[3]) + X[ 0]),  3)
    s1[3] = lrot32((s0[3] + F(s1[0], s0[1], s0[2]) + X[ 1]),  7)
    s1[2] = lrot32((s0[2] + F(s1[3], s1[0], s0[1]) + X[ 2]), 11)
    s1[1] = lrot32((s0[1] + F(s1[2], s1[3], s1[0]) + X[ 3]), 19)

    s2 = [0, 0, 0, 0]

    s2[0] = lrot32((s1[0] + F(s1[1], s1[2], s1[3]) + X[ 4]),  3)
    s2[3] = lrot32((s1[3] + F(s2[0], s1[1], s1[2]) + X[ 5]),  7)
    s2[2] = lrot32((s1[2] + F(s2[3], s2[0], s1[1]) + X[ 6]), 11)
    s2[1] = lrot32((s1[1] + F(s2[2], s2[3], s2[0]) + X[ 7]), 19)

    s3 = [0, 0, 0, 0]

    s3[0] = lrot32((s2[0] + F(s2[1], s2[2], s2[3]) + X[ 8]),  3)
    s3[3] = lrot32((s2[3] + F(s3[0], s2[1], s2[2]) + X[ 9]),  7)
    s3[2] = lrot32((s2[2] + F(s3[3], s3[0], s2[1]) + X[10]), 11)
    s3[1] = lrot32((s2[1] + F(s3[2], s3[3], s3[0]) + X[11]), 19)

    s4 = [0, 0, 0, 0]

    s4[0] = lrot32((s3[0] + F(s3[1], s3[2], s3[3]) + X[12]),  3)
    s4[3] = lrot32((s3[3] + F(s4[0], s3[1], s3[2]) + X[13]),  7)
    s4[2] = lrot32((s3[2] + F(s4[3], s4[0], s3[1]) + X[14]), 11)
    s4[1] = lrot32((s3[1] + F(s4[2], s4[3], s4[0]) + X[15]), 19)

    return [s1, s2, s3, s4]

#round 2 table - [abcd k s]
_round2 = [
    [0,1,2,3, 0,3],
    [3,0,1,2, 4,5],
    [2,3,0,1, 8,9],
    [1,2,3,0, 12,13],

    [0,1,2,3, 1,3],
    [3,0,1,2, 5,5],
    [2,3,0,1, 9,9],
    [1,2,3,0, 13,13],

    [0,1,2,3, 2,3],
    [3,0,1,2, 6,5],
    [2,3,0,1, 10,9],
    [1,2,3,0, 14,13],

    [0,1,2,3, 3,3],
    [3,0,1,2, 7,5],
    [2,3,0,1, 11,9],
    [1,2,3,0, 15,13],
]

ROUND2_K = 0x5a827999

def do_round2(X, s4):
    #round 2 - G function

    s5 = [0, 0, 0, 0]

    s5[0] = lrot32((s4[0] + G(s4[1], s4[2], s4[3]) + X[ 0] + ROUND2_K),  3)
    s5[3] = lrot32((s4[3] + G(s5[0], s4[1], s4[2]) + X[ 4] + ROUND2_K),  5)
    s5[2] = lrot32((s4[2] + G(s5[3], s5[0], s4[1]) + X[ 8] + ROUND2_K),  9)
    s5[1] = lrot32((s4[1] + G(s5[2], s5[3], s5[0]) + X[12] + ROUND2_K), 13)

    s6 = [0, 0, 0, 0]

    s6[0] = lrot32((s5[0] + G(s5[1], s5[2], s5[3]) + X[ 1] + ROUND2_K),  3)
    s6[3] = lrot32((s5[3] + G(s6[0], s5[1], s5[2]) + X[ 5] + ROUND2_K),  5)
    s6[2] = lrot32((s5[2] + G(s6[3], s6[0], s5[1]) + X[ 9] + ROUND2_K),  9)
    s6[1] = lrot32((s5[1] + G(s6[2], s6[3], s6[0]) + X[13] + ROUND2_K), 13)

    s7 = [0, 0, 0, 0]

    s7[0] = lrot32((s6[0] + G(s6[1], s6[2], s6[3]) + X[ 2] + ROUND2_K),  3)
    s7[3] = lrot32((s6[3] + G(s7[0], s6[1], s6[2]) + X[ 6] + ROUND2_K),  5)
    s7[2] = lrot32((s6[2] + G(s7[3], s7[0], s6[1]) + X[10] + ROUND2_K),  9)
    s7[1] = lrot32((s6[1] + G(s7[2], s7[3], s7[0]) + X[14] + ROUND2_K), 13)

    s8 = [0, 0, 0, 0]

    s8[0] = lrot32((s7[0] + G(s7[1], s7[2], s7[3]) + X[ 3] + ROUND2_K),  3)
    s8[3] = lrot32((s7[3] + G(s8[0], s7[1], s7[2]) + X[ 7] + ROUND2_K),  5)
    s8[2] = lrot32((s7[2] + G(s8[3], s8[0], s7[1]) + X[11] + ROUND2_K),  9)
    s8[1] = lrot32((s7[1] + G(s8[2], s8[3], s8[0]) + X[15] + ROUND2_K), 13)

    return [s5, s6, s7, s8]

#round 3 table - [abcd k s]
_round3 = [
    [0,1,2,3, 0,3],
    [3,0,1,2, 8,9],
    [2,3,0,1, 4,11],
    [1,2,3,0, 12,15],

    [0,1,2,3, 2,3],
    [3,0,1,2, 10,9],
    [2,3,0,1, 6,11],
    [1,2,3,0, 14,15],

    [0,1,2,3, 1,3],
    [3,0,1,2, 9,9],
    [2,3,0,1, 5,11],
    [1,2,3,0, 13,15],

    [0,1,2,3, 3,3],
    [3,0,1,2, 11,9],
    [2,3,0,1, 7,11],
    [1,2,3,0, 15,15],
]

def do_round3(X, state):
    state = list(state)
    states = []
    #round 3 - H function - x ^ y ^ z
    for i, (a,b,c,d,k,s) in enumerate(_round3):
        t = (state[a] + (state[b] ^ state[c] ^ state[d]) + X[k] + 0x6ed9eba1) & MASK_32
        state[a] = ((t<<s) & MASK_32) + (t>>(32-s))
        if i % 4 == 3:
            states.append(list(state))
    return states

#=========================================================================
#main class
#=========================================================================
class md4(object):
    """pep-247 compatible implementation of MD4 hash algorithm

    .. attribute:: digest_size

        size of md4 digest in bytes (16 bytes)

    .. method:: update

        update digest by appending additional content

    .. method:: copy

        create clone of digest object, including current state

    .. method:: digest

        return bytes representing md4 digest of current content

    .. method:: hexdigest

        return hexdecimal version of digest
    """
    #FIXME: make this follow hash object PEP better.
    #FIXME: this isn't threadsafe
    #XXX: should we monkeypatch ourselves into hashlib for general use? probably wouldn't be nice.

    name = "md4"
    digest_size = digestsize = 16

    _count = 0 #number of 64-byte blocks processed so far (not including _buf)
    _state = None #list of [a,b,c,d] 32 bit ints used as internal register
    _buf = None #data processed in 64 byte blocks, this holds leftover from last update

    def __init__(self, initial_state=None):
        self._count = 0
        if initial_state:
            self._state = list(initial_state)
        else:
            self._state = list(INITIAL_STATE)
        self._buf = b''

    def _process(self, block):
        "process 64 byte block"
        #unpack block into 16 32-bit ints
        X = struct.unpack("<16I", block)

        round1_states = do_round1(X, self._state)
        round2_states = do_round2(X, round1_states[-1])
        round3_states = do_round3(X, round2_states[-1])

        #add back into original state
        for i in range(4):
            self._state[i] = (self._state[i]+round3_states[-1][i]) & MASK_32

    def update(self, content):
        if not isinstance(content, bytes):
            raise TypeError("expected bytes")
        buf = self._buf
        if buf:
            content = buf + content
        idx = 0
        end = len(content)
        while True:
            next = idx + 64
            if next <= end:
                self._process(content[idx:next])
                self._count += 1
                idx = next
            else:
                self._buf = content[idx:]
                return

    def copy(self):
        other = _builtin_md4()
        other._count = self._count
        other._state = list(self._state)
        other._buf = self._buf
        return other

    def state(self):
        return struct.pack("<4I", *self._state)

    def state_be(self):
        return struct.pack(">4I", *self._state)

    def digest(self, msglen=None):
        #NOTE: backing up state so we can restore it after _process is called,
        #in case object is updated again (this is only attr altered by this method)
        orig = list(self._state)

        #final block: buf + 0x80,
        # then 0x00 padding until congruent w/ 56 mod 64 bytes
        # then last 8 bytes = msg length in bits
        buf = self._buf
        if msglen is None:
            msglen = self._count*512 + len(buf)*8
        block = buf + b'\x80' + b'\x00' * ((119-len(buf)) % 64) + \
            struct.pack("<2I", msglen & MASK_32, (msglen>>32) & MASK_32)
        if len(block) == 128:
            self._process(block[:64])
            self._process(block[64:])
        else:
            assert len(block) == 64
            self._process(block)

        #render digest & restore un-finalized state
        out = self.state()
        self._state = orig
        return out

    def hexdigest(self, msglen=None):
        return (hexlify(self.digest(msglen))).decode('ascii')
