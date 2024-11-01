from utils import encrypt, decrypt

class AuthenticationServiceToClientSession:
    def __init__(self, client_key):
        self.client_key = client_key
        
    def generate_session(self, timestamp, ticket_granting_service_name, tgt_validity, client_to_tgs_session_key):
        session_content = f"{timestamp},{ticket_granting_service_name},{tgt_validity},{client_to_tgs_session_key}"
        encrypted_session = encrypt(self.client_key, session_content)
        return encrypted_session
    
    def parse_session(self, encrypted_session):
        decrypted_session = decrypt(self.client_key, encrypted_session)
        timestamp, ticket_granting_service_name, tgt_validity, client_to_ticket_granting_service_session_key = decrypted_session.split(',')
        return timestamp, ticket_granting_service_name, tgt_validity, client_to_ticket_granting_service_session_key