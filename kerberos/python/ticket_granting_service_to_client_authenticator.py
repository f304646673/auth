from utils import encrypt, decrypt

class TicketGrantingServiceToClientAuthenticator:

    def __init__(self, ticket_granting_service_authenticator_key):
        self.ticket_granting_service_authenticator_key = ticket_granting_service_authenticator_key
        
    def generate_authenticator(self, ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key):
        authenticator_content = f"{ticket_granting_service_to_client_timestamp},{biz_service_ticket_validity},{client_to_biz_service_authenticator_key}"
        encrypted_authenticator = encrypt(self.ticket_granting_service_authenticator_key, authenticator_content)
        return encrypted_authenticator
    
    def parse_authenticator(self, encrypted_authenticator):
        decrypted_authenticator = decrypt(self.ticket_granting_service_authenticator_key, encrypted_authenticator)
        ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key = decrypted_authenticator.split(',')
        return ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key