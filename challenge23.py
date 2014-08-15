def getMSB(x, n):
    if n < 0:
        return 0
    return (x >> (31 - n)) & 1

def setMSB(x, n, b):
    return x | (b << (31 - n))

def undoRightShiftXor(y, s):
    z = 0
    for i in range(32):
        z = setMSB(z, i, getMSB(y, i) ^ getMSB(z, i - s))
    return z
