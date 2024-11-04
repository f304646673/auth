from utils import encrypt, decrypt

class ClientToTicketGrantingServiceSession:
    def __init__(self, client_to_ticket_granting_service_session_key):
        self.client_to_ticket_granting_service_session_key = client_to_ticket_granting_service_session_key
        
    def generate_session(self, client_name, client_ip, client_to_ticket_granting_service_timestamp):
        session_content = f"{client_name},{client_ip},{client_to_ticket_granting_service_timestamp}"
        encrypted_session = encrypt(self.client_to_ticket_granting_service_session_key, session_content)
        return encrypted_session
    
    def parse_session(self, encrypted_session):
        decrypted_session = decrypt(self.client_to_ticket_granting_service_session_key, encrypted_session)
        try:
            client_name, client_ip, client_to_ticket_granting_service_timestamp = decrypted_session.split(',')
        except ValueError:
            print("Error: Invalid session: ", decrypted_session)
            return None, None, None
        return client_name, client_ip, client_to_ticket_granting_service_timestamp