import challenge39
import hashlib
import re

def generateSignature(priv, message):
    sha1 = hashlib.sha1()
    sha1.update(message)
    digest = sha1.digest()
    block = b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3)) + b'\x00' + digest
    signature = challenge39.decryptbytes(priv, block)
    return signature

def verifySignature(pub, message, signature):
    block = b'\x00' + challenge39.encryptbytes(pub, signature)
    r = re.compile(b'\x00\x01\xff+?\x00(.{20})', re.DOTALL)
    m = r.match(block)
    if not m:
        return False
    digest = m.group(1)
    sha1 = hashlib.sha1()
    sha1.update(message)
    return digest == sha1.digest()

if __name__ == '__main__':
    message = b'hi mom'
    pub, priv = challenge39.genKey(1024)
    signature = generateSignature(priv, message)
    if not verifySignature(pub, message, signature):
        raise Exception(message + b' has invalid signature ' + signature)
