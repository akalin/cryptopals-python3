import binascii
import challenge49

def insecureHash(s):
    return challenge49.CBC_MAC(b'YELLOW SUBMARINE', b'\x00' * 16, s)

s = b"alert('MZA who was that?');\n"
sHash = insecureHash(s)
print(binascii.hexlify(sHash))
