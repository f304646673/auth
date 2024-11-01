import time
from utils import encrypt, decrypt

class ClientToBizServiceSession:
    def __init__(self, client_to_server_session_key):
        self.client_to_server_session_key = client_to_server_session_key
    
    def generate_session(self, client_name, client_ip, timestamp, server_name):
        session_content = f"{client_name},{client_ip},{timestamp},{server_name}"
        encrypted_session = encrypt(self.client_to_server_session_key, session_content)
        return encrypted_session
    
    def parse_session(self, encrypted_session):
        decrypted_session = decrypt(self.client_to_server_session_key, encrypted_session)
        client_name, client_ip, timestamp, server_name = decrypted_session.split(',')
        return client_name, client_ip, timestamp, server_name