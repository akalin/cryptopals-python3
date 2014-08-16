import binascii
import sys
import urllib.request

def isValidSignature(file, signature):
    try:
        response = urllib.request.urlopen('http://localhost:9000/test?file=' + file + '&signature=' + signature)
        if response.status != 200:
            raise Exception('unexpected status ' + str(response.status))
        return True
    except urllib.error.HTTPError as e:
        if e.code != 500:
            raise Exception('unexpected status ' + str(e.code))
        return False

if __name__ == '__main__':
    file = sys.argv[1]
    signature = '00'
    print(isValidSignature(file, signature))
