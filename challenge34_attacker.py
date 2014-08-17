from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import challenge9
import challenge15
import hashlib
import socket
import socketserver
import sys

targethost = ''
targetport = 0

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

def decrypt(key, iv, encryptedMessage):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return challenge15.unpadPKCS7(cipher.decrypt(encryptedMessage)).decode('ascii')

class AttackerTCPHandler(socketserver.StreamRequestHandler):
    def readline(self):
        return self.rfile.readline().strip()

    def readnum(self):
        return int(self.readline())

    def readbytes(self):
        return base64.b64decode(self.readline())

    def writeline(self, line):
        self.wfile.write(line + b'\n')

    def writenum(self, num):
        self.writeline(str(num).encode('ascii'))

    def writebytes(self, bytes):
        self.writeline(base64.b64encode(bytes))

    def handle(self):
        global targethost
        global targetport

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((targethost, targetport))
            f = sock.makefile(mode='rwb', buffering=0)

            print('C->A: reading p...')
            p = self.readnum()

            print('C->A: reading g...')
            g = self.readnum()

            print('C->A: reading A...')
            A = self.readnum()

            print('A->S: writing p...')
            writenum(f, p)

            print('A->S: writing g...')
            writenum(f, g)

            print('A->S: writing p...')
            writenum(f, p)

            print('S->A: reading B...')
            B = readnum(f)

            print('A->C: writing p...')
            self.writenum(p)

            print('C->A: reading encrypted message...')
            encryptedMessage = self.readbytes()

            print('A->S: writing encrypted message...')
            writebytes(f, encryptedMessage)

            print('C->A: reading iv...')
            iv = self.readbytes()

            print('A->S: writing iv...')
            writebytes(f, iv)

            print('S->A: reading encrypted message...')
            encryptedMessage2 = readbytes(f)

            print('A->C: writing encrypted message...')
            self.writebytes(encryptedMessage2)

            print('S->A: reading iv...')
            iv2 = readbytes(f)

            print('A->C: writing iv...')
            self.writebytes(iv2)

            key = derivekey(0)
            message = decrypt(key, iv, encryptedMessage)

            print('A: message: ' + message)

        finally:
            sock.close()

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    targethost = sys.argv[3]
    targetport = int(sys.argv[4])

    print('listening on ' + host + ':' + str(port) + ', attacking ' + targethost + ':' + str(targetport))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), AttackerTCPHandler)

    server.serve_forever()
