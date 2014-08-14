from Crypto.Cipher import AES
import base64
import binascii
import challenge18

strings = [
    b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    b'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    b'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    b'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
]

# Generated randomly.
key = b'\xa3\xc9\xe7\xedmZU\x1e\xac\x15\xe2\xaf\xb4$\xa9{'

def encryptString(s):
    cipher = challenge18.CTR(AES.new(key, AES.MODE_ECB), 0)
    return cipher.encrypt(s)

encryptedStrings = [encryptString(base64.b64decode(s)) for s in strings]

for x in encryptedStrings:
    print(binascii.hexlify(x))
