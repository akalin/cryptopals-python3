from Crypto.Random import random

def doDiffieHellman(p, g):
    a = random.randint(0, p)
    A = (g**a) % p
    b = random.randint(0, p)
    B = (g**b) % p
    return (a, A, b, B)

if __name__ == '__main__':
    p = 37
    g = 5
    a, A, b, B = doDiffieHellman(p, g)
    print(a, A, b, B)
    sA = (B**a) % p
    sB = (A**b) % p
    if sA != sB:
        print(str(sA) + ' != ' + str(sB))
    print(sA)
