import time
from utils import encrypt, decrypt

class BizServiceTicket:
    def __init__(self, server_key):
        self.server_key = server_key
    
    def generate_service_ticket(self, client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key):
        st_content = f"{client_id},{client_ip},{server_name},{timestamp},{st_validity},{client_to_server_session_key}"
        encrypted_st = encrypt(self.server_key, st_content)
        return encrypted_st
    
    def parse_tgs_ticket(self, encrypted_st):
        decrypted_st = decrypt(self.server_key, encrypted_st)
        client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key = decrypted_st.split(',')
        return client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key
        