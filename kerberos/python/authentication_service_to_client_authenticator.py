import rsa
from utils import encrypt, decrypt

class AuthenticationServiceToClientAuthenticator:
    def __init__(self, client_key):
        self.client_key = client_key
        
    def generate_authenticator(self, authentication_service_to_client_timestamp, ticket_granting_service_name, 
                               ticket_granting_service_ticket_validity, client_to_ticket_granting_service_authenticator_key):
        authenticator_content = f"{authentication_service_to_client_timestamp},{ticket_granting_service_name},{ticket_granting_service_ticket_validity},{client_to_ticket_granting_service_authenticator_key}"
        encrypted_authenticator = rsa.encrypt_rsa(self.client_key, authenticator_content)
        return encrypted_authenticator
    
    def parse_authenticator(self, encrypted_authenticator):
        decrypted_authenticator = rsa.decrypt_rsa(self.client_key, encrypted_authenticator)
        try:
            authentication_service_to_client_timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity,\
                client_to_ticket_granting_service_authenticator_key = decrypted_authenticator.split(',')
        except:
            print("Error: Invalid authenticator: ", decrypted_authenticator)
            return None, None, None, None
        
        return authentication_service_to_client_timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, \
            client_to_ticket_granting_service_authenticator_key