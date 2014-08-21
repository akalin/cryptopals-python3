import hashlib
import challenge39

decryptedHashes = set()

pub, priv = challenge39.genKey(128)

def encrypt(plaintext):
    return challenge39.encryptbytes(pub, plaintext)

def decryptOnce(ciphertext):
    sha1 = hashlib.sha1()
    sha1.update(ciphertext)
    digest = sha1.digest()
    if digest in decryptedHashes:
        raise ValueError('Already decrypted')
    decryptedHashes.add(digest)
    return challenge39.decryptbytes(priv, ciphertext)

if __name__ == '__main__':
    plaintext = b'secret text'
    ciphertext = encrypt(plaintext)
    plaintext2 = decryptOnce(ciphertext)
    if plaintext2 != plaintext:
        raise ValueError(plaintext2 + b' != ' + plaintext)
    # TODO(akalin): Munge ciphertext to decrypt it again.
    decryptOnce(ciphertext)
