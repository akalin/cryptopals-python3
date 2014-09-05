from Crypto.Random import random

def randbytes(k):
    return random.getrandbits(8*k).to_bytes(k, byteorder='big')
