from Cryptodome.Random import random
import challenge34_shared
import socket
import socketserver
import sys

targethost = ''
targetport = 0

class AttackerTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        global targethost
        global targetport

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((targethost, targetport))
            serverconn = challenge34_shared.Conn(sock)
            clientconn = challenge34_shared.Conn(self)

            print('C->A: reading p...')
            p = clientconn.readnum()

            print('C->A: reading g...')
            g = clientconn.readnum()

            print('C->A: reading A...')
            A = clientconn.readnum()

            print('A->S: writing p...')
            serverconn.writenum(p)

            print('A->S: writing g...')
            serverconn.writenum(g)

            print('A->S: writing p...')
            serverconn.writenum(p)

            print('S->A: reading B...')
            B = serverconn.readnum()

            print('A->C: writing p...')
            clientconn.writenum(p)

            print('C->A: reading encrypted message...')
            encrypted_message = clientconn.readbytes()

            print('A->S: writing encrypted message...')
            serverconn.writebytes(encrypted_message)

            print('C->A: reading iv...')
            iv = clientconn.readbytes()

            print('A->S: writing iv...')
            serverconn.writebytes(iv)

            print('S->A: reading encrypted message...')
            encrypted_message2 = serverconn.readbytes()

            print('A->C: writing encrypted message...')
            clientconn.writebytes(encrypted_message2)

            print('S->A: reading iv...')
            iv2 = serverconn.readbytes()

            print('A->C: writing iv...')
            clientconn.writebytes(iv2)

            key = challenge34_shared.derivekey(0)
            message = challenge34_shared.decrypt(key, iv, encrypted_message)

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
