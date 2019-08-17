def padPKCS7(x, k):
    ch = k - (len(x) % k)
    return x + bytes([ch] * ch)

def rrot32(x, n):
    x = x & 0xffffffff
    return (x >> n) | ((x << (32 - n)) & 0xffffffff)

def lrot32(x, n):
    return rrot32(x, 32 - n)
