# utils.py
import base64
import random
import string
from Crypto.Cipher import AES

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

def generate_random_key(length=16):
    """
    生成一个随机的16个字符的字符串
    """
    characters = string.ascii_letters + string.digits
    random_key = ''.join(random.choice(characters) for i in range(length))
    return random_key