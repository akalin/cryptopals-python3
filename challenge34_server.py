from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import challenge9
import challenge11
import challenge15
import hashlib
import socketserver
import sys

class DiffieHellmanTCPHandler(socketserver.StreamRequestHandler):
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

    def derivekey(self, s):
        sha1 = hashlib.sha1()
        sha1.update(str(s).encode('ascii'))
        return sha1.digest()[:16]

    def encrypt(self, key, iv, message):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(challenge9.padPKCS7(message.encode('ascii'), 16))

    def decrypt(self, key, iv, encryptedMessage):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return challenge15.unpadPKCS7(cipher.decrypt(encryptedMessage)).decode('ascii')

    def handle(self):
        print('S: reading p...')
        p = self.readnum()

        print('S: reading g...')
        g = self.readnum()

        print('S: reading A...')
        A = self.readnum()

        b = random.randint(0, p)
        B = pow(g, b, p)

        print('S: writing B...')
        self.writenum(B)

        s = pow(A, b, p)
        key = self.derivekey(s)

        print('S: reading encrypted message...')
        encryptedMessage = self.readbytes()

        print('S: reading iv...')
        iv = self.readbytes()

        message = self.decrypt(key, iv, encryptedMessage)
        print('S: message:', message)

        encryptedMessage2 = self.encrypt(key, iv, message)
        if encryptedMessage2 != encryptedMessage:
            raise Exception(encryptedMessage2 + b' != ' + encryptedMessage)

        print('S: writing encrypted message...')
        self.writebytes(encryptedMessage2)

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])

    print('listening on ' + host + ':' + str(port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), DiffieHellmanTCPHandler)

    server.serve_forever()
