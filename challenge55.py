import md4

def assert_md4(m, expected_h):
    md4obj = md4.md4()
    md4obj.update(m)
    h = md4obj.hexdigest()
    if h != expected_h:
        raise Exception('expected {}, got {}'.format(expected_h, h))

def test_md4():
    # Taken from https://en.wikipedia.org/wiki/MD4 .
    assert_md4(b'', '31d6cfe0d16ae931b73c59d7e0c089c0')
    assert_md4(b'a', 'bde52cb31de33e46245e05fbdbd6fb24')
    assert_md4(b'abc', 'a448017aaf21d8525fc10ae87aa6729d')
    assert_md4(b'message digest', 'd9130a8164549fe818874806e1c7014b')
    assert_md4(b'abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9')
    assert_md4(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', '043f8582f241db351ce627e153e7f0e4')
    assert_md4(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'e33b4ddc9c38f2199c3e7b164fcc0536')

if __name__ == '__main__':
    test_md4()
