from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import challenge9
import challenge11
import challenge15
import hashlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
message = sys.argv[3]

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
a = random.randint(0, p)
A = pow(g, a, p)

def readline(f):
    return f.readline().strip()

def readnum(f):
    return int(readline(f))

def readbytes(f):
    return base64.b64decode(readline(f))

def writeline(f, line):
    f.write(line + b'\n')

def writenum(f, num):
    writeline(f, str(num).encode('ascii'))

def writebytes(f, bytes):
    writeline(f, base64.b64encode(bytes))

def derivekey(s):
    sha1 = hashlib.sha1()
    sha1.update(str(s).encode('ascii'))
    return sha1.digest()[:16]

def encrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(challenge9.padPKCS7(message.encode('ascii'), 16))

def decrypt(key, iv, encryptedMessage):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return challenge15.unpadPKCS7(cipher.decrypt(encryptedMessage)).decode('ascii')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((host, port))
    f = sock.makefile(mode='rwb', buffering=0)

    print('C: writing p...')
    writenum(f, p)

    print('C: writing g...')
    writenum(f, g)

    print('C: writing A...')
    writenum(f, A)

    print('C: reading B...')
    B = readnum(f)

    s = pow(B, a, p)
    key = derivekey(s)

    iv = challenge11.randbytes(16)
    encryptedMessage = encrypt(key, iv, message)

    print('C: writing encrypted message...')
    writebytes(f, encryptedMessage)

    print('C: writing iv...')
    writebytes(f, iv)

    print('C: reading encrypted message...')
    encryptedMessage2 = readbytes(f)
    message2 = decrypt(key, iv, encryptedMessage2)
    if message2 != message:
        raise Exception(message2 + ' != ' + message)
finally:
    sock.close()
