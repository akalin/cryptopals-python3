import binascii
import http.server
import socketserver
import urllib.parse

PORT = 9000

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        result = urllib.parse.urlparse(self.path)
        if result.path == '/test':
            q = urllib.parse.parse_qs(result.query)
            file = q['file'][0].encode('ascii')
            signature = binascii.unhexlify(q['signature'][0])
            print(file, signature)
            self.send_error(200)
        else:
            self.send_error(500)

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("", PORT), RequestHandler)
print("serving at port", PORT)
httpd.serve_forever()
