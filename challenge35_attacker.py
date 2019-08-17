import challenge34_shared
import socket
import socketserver
import sys

targethost = ''
targetport = 0
targetg = 0

class AttackerTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        global targethost
        global targetport
        global targetg

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((targethost, targetport))
            serverconn = challenge34_shared.Conn(sock)
            clientconn = challenge34_shared.Conn(self)

            print('C->A: reading p...')
            p = clientconn.readnum()

            print('C->A: reading g...')
            g = clientconn.readnum()

            print('A->S: writing p...')
            serverconn.writenum(p)

            if targetg > 0:
                fakeg = 1
            elif targetg < 0:
                fakeg = p - 1
            else:
                fakeg = p

            print('A->S: writing fake g...')
            serverconn.writenum(fakeg)

            print('S->A: reading p...')
            serverconn.readnum()

            print('S->A: reading g...')
            serverconn.readnum()

            print('A->C: writing p...')
            clientconn.writenum(p)

            print('A->C: writing fake g...')
            clientconn.writenum(fakeg)

            print('C->A: reading A...')
            A = clientconn.readnum()

            print('A->S: writing A...')
            serverconn.writenum(A)

            print('S->A: reading B...')
            B = serverconn.readnum()

            print('A->C: writing B...')
            clientconn.writenum(B)

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

            if targetg > 0:
                s = 1
            elif targetg < 0:
                if A == p - 1 and B == p - 1:
                    s = p - 1
                else:
                    s = 1
            else:
                s = 0
            key = challenge34_shared.derivekey(s)
            message = challenge34_shared.decrypt(key, iv, encrypted_message)

            print('A: message: ' + message)

        finally:
            sock.close()

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    targethost = sys.argv[3]
    targetport = int(sys.argv[4])
    targetg = int(sys.argv[5])

    print('listening on ' + host + ':' + str(port) + ', attacking ' + targethost + ':' + str(targetport))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), AttackerTCPHandler)

    server.serve_forever()
