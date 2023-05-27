from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import randint
import socket
import sys
import challenge34_shared

host = sys.argv[1]
port = int(sys.argv[2])
message = sys.argv[3]

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
a = randint(0, p)
A = pow(g, a, p)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((host, port))
    conn = challenge34_shared.Conn(sock)

    print('C: writing p...')
    conn.writenum(p)

    print('C: writing g...')
    conn.writenum(g)

    print('C: writing A...')
    conn.writenum(A)

    print('C: reading B...')
    B = conn.readnum()

    s = pow(B, a, p)
    key = challenge34_shared.derivekey(s)

    iv = get_random_bytes(16)
    encrypted_message = challenge34_shared.encrypt(key, iv, message)

    print('C: writing encrypted message...')
    conn.writebytes(encrypted_message)

    print('C: writing iv...')
    conn.writebytes(iv)

    print('C: reading encrypted message...')
    encrypted_message2 = conn.readbytes()
    message2 = challenge34_shared.decrypt(key, iv, encrypted_message2)
    if message2 != message:
        raise Exception(message2 + ' != ' + message)
finally:
    sock.close()
