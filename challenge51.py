from Crypto.Cipher import AES
from Crypto.Util import Counter
import string
import util
import zlib

def format_request(P):
    return '''POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {0}
{1}'''.format(len(P), P)

def oracle(P):
    request = format_request(P)
    compressed_request = zlib.compress(request.encode('ascii'))
    key = util.randbytes(16)
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    encrypted_request = cipher.encrypt(compressed_request)
    return len(encrypted_request)

alphabet = string.ascii_letters + string.digits + '+/='

def guessNextByte(oracle, knownStr):
    min_ch = ''
    min_ch_sz = 0
    for i in range(len(alphabet)):
        ch = alphabet[i]
        s = 'sessionid=' + knownStr + ch
        sz = oracle(s * 8)
        if min_ch == '' or sz < min_ch_sz:
            min_ch = ch
            min_ch_sz = sz
    return min_ch

knownStr = ''
for i in range(0, 1):
    knownStr += guessNextByte(oracle, knownStr)
    print(knownStr)
