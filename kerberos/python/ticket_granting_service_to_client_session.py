from utils import encrypt, decrypt

class TicketGrantingServiceToClientSession:

    def __init__(self, ticket_granting_service_session_key):
        self.ticket_granting_service_session_key = ticket_granting_service_session_key
        
    def generate_session(self, timestamp, st_timestamp, client_to_biz_service_session_key):
        session_content = f"{timestamp},{st_timestamp},{client_to_biz_service_session_key}"
        encrypted_session = encrypt(self.ticket_granting_service_session_key, session_content)
        return encrypted_session