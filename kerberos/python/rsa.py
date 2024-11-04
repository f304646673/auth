from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_key_pair():
    """
    生成RSA私钥和公钥
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(public_key, message):
    """
    使用公钥加密消息
    """
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return encrypted_message

def decrypt_rsa(private_key, encrypted_message):
    """
    使用私钥解密消息
    """
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# # 示例用法
if __name__ == "__main__":
    # 生成密钥对
    for i in range(3):
        private_key, public_key = generate_key_pair()
        print(f"Private key: \n{private_key.decode()}\n, Public key: \n{public_key.decode()}")
    