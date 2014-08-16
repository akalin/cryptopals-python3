import struct

def padSHA1(s):
    l = len(s) * 8
    s += b'\x80'
    s += b'\x00' * ((56 - (len(s) % 64)) % 64)
    s += struct.pack('>Q', l)
    return s
