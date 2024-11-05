from utils import encrypt, decrypt

class ClientToTicketGrantingServiceAuthenticator:
    def __init__(self, client_to_ticket_granting_service_authenticator_key):
        self.client_to_ticket_granting_service_authenticator_key = client_to_ticket_granting_service_authenticator_key
        
    def generate_authenticator(self, client_name, client_ip, client_to_ticket_granting_service_timestamp):
        authenticator_content = f"{client_name},{client_ip},{client_to_ticket_granting_service_timestamp}"
        encrypted_authenticator = encrypt(self.client_to_ticket_granting_service_authenticator_key, authenticator_content)
        return encrypted_authenticator
    
    def parse_authenticator(self, encrypted_authenticator):
        decrypted_authenticator = decrypt(self.client_to_ticket_granting_service_authenticator_key, encrypted_authenticator)
        try:
            client_name, client_ip, client_to_ticket_granting_service_timestamp = decrypted_authenticator.split(',')
        except:
            print("Error: Invalid authenticator: ", decrypted_authenticator)
            return None, None, None
        return client_name, client_ip, client_to_ticket_granting_service_timestamp