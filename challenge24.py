from Crypto.Util.strxor import strxor
import challenge21
import struct

class MT19937Cipher:
    def __init__(self, key):
        self._rng = challenge21.MT19937(key & 0xffff)
        self._keybytes = b''

    def encrypt(self, plaintext):
        # Work around strxor() not handling zero-length strings
        # gracefully.
        if len(plaintext) == 0:
            return b''

        keystream = self._keybytes
        while len(keystream) < len(plaintext):
            keyblock = struct.pack('<L', self._rng.uint32())
            keystream += keyblock

        if len(keystream) > len(plaintext):
            self._keybytes = keystream[len(plaintext):]
            keystream = keystream[:len(plaintext)]

        return strxor(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
