from Crypto.Util.strxor import strxor
import binascii
import challenge49
import util

def insecureHash(s):
    return challenge49.CBC_MAC(b'YELLOW SUBMARINE', b'\x00' * 16, s)

def prependAndCollide(s, prefix):
    prefixHash = insecureHash(prefix)
    paddedPrefix = util.padPKCS7(prefix, 16)
    return paddedPrefix + strxor(s[:16], prefixHash) + s[16:]

s = b"alert('MZA who was that?');\n"
sHash = insecureHash(s)
print(binascii.hexlify(sHash))

prefix = b"alert('Ayo, the Wu is back!'); //"
collision = prependAndCollide(s, prefix)
print(collision, binascii.hexlify(insecureHash(collision)))
