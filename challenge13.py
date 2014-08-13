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
