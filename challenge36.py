from Cryptodome.Random import random
import hmac
import socket
import sys
import challenge34_shared
import challenge36_util

host = sys.argv[1]
port = int(sys.argv[2])
email = sys.argv[3]
password = sys.argv[4]

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

a = random.randint(0, N)
A = pow(g, a, N)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((host, port))
    conn = challenge34_shared.Conn(sock)

    print('C: writing email...')
    conn.writeline(email.encode('ascii'))

    print('C: writing A...')
    conn.writenum(A)

    print('C: reading salt...')
    salt = conn.readnum()

    print('C: reading B...')
    B = conn.readnum()

    u = challenge36_util.hashToInt(str(A) + str(B))
    x = challenge36_util.hashToInt(str(salt) + password)
    S = pow(B - k * pow(g, x, N), a + u * x, N)

    K = challenge36_util.hashToBytes(str(S))

    client_hmac = challenge36_util.hmac(salt, K)

    print('C: writing hmac...')
    conn.writebytes(client_hmac)

    print('C: reading result...')
    result = conn.readline()

    print('result:', result)
finally:
    sock.close()
