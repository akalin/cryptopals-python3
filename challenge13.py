from Crypto.Cipher import AES
import challenge9
import challenge11

def encode_profile(profile):
    s = b''
    def sanitize(s):
        return s.replace(b'&', b'').replace(b'=', b'')
    for kv in profile:
        sanitizedKV = [sanitize(x.encode('ascii')) for x in kv]
        if s != b'':
            s += b'&'
        s += sanitizedKV[0] + b'=' + sanitizedKV[1]
    return s

def profile_for(email):
    profile = [
        ['email', email],
        ['uid', '10'],
        ['role', 'user']
        ]
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
    profile = []
    for p in pairs:
        profile += [[x.decode('ascii') for x in p.split(b'=')]]
    return profile

email = 'foo@bar.com'
x = encrypt_profile_for(email)
# TODO(akalin): Munge x into a profile with an admin role.
y = decrypt_profile(x)
print(email, x, y)
