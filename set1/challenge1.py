import base64
import struct

def hexToBase64(s):
    decoded = ''.join([chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2)])
    return base64.b64encode(decoded.encode('ascii')).decode('ascii')

x = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
expectedY = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
y = hexToBase64(x)
print(y)
print(expectedY)
if y != expectedY:
    raise Exception(y + ' != ' + expectedY)
