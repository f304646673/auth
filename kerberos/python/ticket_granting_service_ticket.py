import time
from utils import encrypt, decrypt

class TicketGrantingServiceTicket:
    def __init__(self, tgs_key):
        self.tgs_key = tgs_key
    
    def generate_tgs_ticket(self, client_id, client_ip, timestamp, tgs_name, tgs_validity, client_to_tgs_session_key):
        tgt_content = f"{client_id},{client_ip},{timestamp},{tgs_name},{tgs_validity},{client_to_tgs_session_key}"
        encrypted_tgt = encrypt(self.tgs_key, tgt_content)
        return encrypted_tgt

    def parse_tgs_ticket(self, encrypted_tgt):
        decrypted_tgt = decrypt(self.tgs_key, encrypted_tgt)
        client_id, client_ip, timestamp, tgs_name, tgt_validity, client_to_tgs_session_key = decrypted_tgt.split(',')
        return client_id, client_ip, timestamp, tgs_name, tgt_validity, client_to_tgs_session_key