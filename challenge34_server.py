from Crypto.Random import random
import challenge34_shared
import socketserver
import sys

class DiffieHellmanTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = challenge34_shared.Conn(self)

        print('S: reading p...')
        p = conn.readnum()

        print('S: reading g...')
        g = conn.readnum()

        print('S: reading A...')
        A = conn.readnum()

        b = random.randint(0, p)
        B = pow(g, b, p)

        print('S: writing B...')
        conn.writenum(B)

        s = pow(A, b, p)
        key = challenge34_shared.derivekey(s)

        print('S: reading encrypted message...')
        encrypted_message = conn.readbytes()

        print('S: reading iv...')
        iv = conn.readbytes()

        message = challenge34_shared.decrypt(key, iv, encrypted_message)
        print('S: message:', message)

        encrypted_message2 = challenge34_shared.encrypt(key, iv, message)
        if encrypted_message2 != encrypted_message:
            raise Exception(encrypted_message2 + b' != ' + encrypted_message)

        print('S: writing encrypted message...')
        conn.writebytes(encrypted_message2)

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])

    print('listening on ' + host + ':' + str(port))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), DiffieHellmanTCPHandler)

    server.serve_forever()
