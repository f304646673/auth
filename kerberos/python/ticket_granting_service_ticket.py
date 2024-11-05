import time
import rsa

class TicketGrantingServiceTicket:
    def __init__(self, ticket_granting_service_key):
        self.ticket_granting_service_key = ticket_granting_service_key
    
    def generate_ticket_granting_service_ticket(self, client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_service_validity, client_to_ticket_granting_service_authenticator_key):
        ticket_granting_service_ticket_content = f"{client_name},{client_ip},{timestamp},{ticket_granting_service_name},{ticket_granting_service_validity},{client_to_ticket_granting_service_authenticator_key}"
        encrypted_ticket_granting_ticket = rsa.encrypt_rsa(self.ticket_granting_service_key, ticket_granting_service_ticket_content)
        return encrypted_ticket_granting_ticket

    def parse_ticket_granting_service_ticket(self, encrypted_ticket_granting_ticket):
        decrypted_ticket_granting_service_ticket = rsa.decrypt_rsa(self.ticket_granting_service_key, encrypted_ticket_granting_ticket)
        try:
            client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_ticket_validity,\
                client_to_ticket_granting_service_authenticator_key = decrypted_ticket_granting_service_ticket.split(',')
        except:
            print("Error: Invalid ticket granting service ticket: ", decrypted_ticket_granting_service_ticket)
            return None, None, None, None, None, None
        
        return client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_ticket_validity,\
                client_to_ticket_granting_service_authenticator_key