import binascii
import sys
import time
import urllib.request

def isValidSignature(file, signature):
    start = time.perf_counter()
    try:
        response = urllib.request.urlopen('http://localhost:9000/test?file=' + file + '&signature=' + signature)
        end = time.perf_counter()
        if response.status != 200:
            raise Exception('unexpected status ' + str(response.status))
        return (True, end - start)
    except urllib.error.HTTPError as e:
        end = time.perf_counter()
        if e.code != 500:
            raise
        return (False, end - start)

if __name__ == '__main__':
    file = sys.argv[1]
    signature = '00'
    print(isValidSignature(file, signature))
