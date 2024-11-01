import rsa
from utils import encrypt, decrypt

class AuthenticationServiceToClientSession:
    def __init__(self, client_key):
        self.client_key = client_key
        
    def generate_session(self, timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key):
        session_content = f"{timestamp},{ticket_granting_service_name},{ticket_granting_service_ticket_validity},{client_to_ticket_granting_service_session_key}"
        encrypted_session = rsa.encrypt_rsa(self.client_key, session_content)
        return encrypted_session
    
    def parse_session(self, encrypted_session):
        decrypted_session = rsa.decrypt_rsa(self.client_key, encrypted_session)
        try:
            timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key = decrypted_session.split(',')
        except:
            print("Error: Invalid session: ", decrypted_session)
            return None, None, None, None
        
        return timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key