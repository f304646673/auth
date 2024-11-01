import time
from utils import encrypt, decrypt

class TicketGrantingTicket:
    def __init__(self) -> None:
        pass
    
    def generate_tgs_ticket(self, tgs_key, client_id, client_ip, timestamp, tgs_name, tgs_validity, client_to_tgs_session_key):
        tgt_content = f"{client_id},{client_ip},{timestamp},{tgs_name},{tgs_validity},{client_to_tgs_session_key}"
        encrypted_tgt = encrypt(tgs_key, tgt_content)
        return encrypted_tgt
    
    def parse_tgs_ticket(self, tgs_key, encrypted_tgt):
        decrypted_tgt = decrypt(tgs_key, encrypted_tgt)
        client_id, client_ip, timestamp, tgs_name, tgt_validity, client_to_tgs_session_key = decrypted_tgt.split(',')
        return client_id, client_ip, timestamp, tgs_name, tgt_validity, client_to_tgs_session_key
    
    
    def generate_service_ticket(self, server_key, client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key):
        st_content = f"{client_id},{client_ip},{server_name},{timestamp},{st_validity},{client_to_server_session_key}"
        encrypted_st = encrypt(server_key, st_content)
        return encrypted_st
    
    def parse_tgs_ticket(self, server_key, encrypted_st):
        decrypted_st = decrypt(server_key, encrypted_st)
        client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key = decrypted_st.split(',')
        return client_id, client_ip, server_name, timestamp, st_validity, client_to_server_session_key
        