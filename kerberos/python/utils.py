# utils.py
from Crypto.Cipher import AES
import base64

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(key, raw):
    raw = pad(raw)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(raw.encode('utf8'))).decode('utf8')

def decrypt(key, enc):
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    return unpad(cipher.decrypt(enc)).decode('utf8')