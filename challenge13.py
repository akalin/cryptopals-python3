from Crypto.Cipher import AES
import challenge9
import challenge11

def encode_profile(profile):
    s = b''
    def sanitize(s):
        return s.replace(b'&', b'').replace(b'=', b'')
    for k in profile:
        sanitizedK = sanitize(k.encode('ascii'))
        sanitizedV = sanitize(profile[k].encode('ascii'))
        if s != b'':
            s += b'&'
        s += sanitizedK + b'=' + sanitizedV
    return s

def profile_for(email):
    profile = {
        'email': email,
        'uid': '10',
        'role': 'user'
        }
    return encode_profile(profile)

key = challenge11.randbytes(16)

def encrypt_profile_for(email):
    cipher = AES.new(key, AES.MODE_ECB)
    encoded_profile = challenge9.padPKCS7(profile_for(email), 16)
    return cipher.encrypt(encoded_profile)

def unpadPKCS7(s, k):
    i = s[-1]
    return s[0:-i]

def decrypt_profile(s):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_profile = unpadPKCS7(cipher.decrypt(s), 16)
    pairs = decrypted_profile.split(b'&')
    d = {}
    for p in pairs:
        p = p.split(b'=')
        d[p[0].decode('ascii')] = p[1].decode('ascii')
    return d

email = 'foo@bar.com'
x = encrypt_profile_for(email)
# TODO(akalin): Munge x into a profile with an admin role.
y = decrypt_profile(x)
print(email, x, y)
