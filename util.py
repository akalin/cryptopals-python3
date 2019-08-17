def padPKCS7(x, k):
    ch = k - (len(x) % k)
    return x + bytes([ch] * ch)
