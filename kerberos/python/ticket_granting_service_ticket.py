import time
from utils import encrypt, decrypt

class TicketGrantingServiceTicket:
    def __init__(self, ticket_granting_service_key):
        self.ticket_granting_service_key = ticket_granting_service_key
    
    def generate_tgs_ticket(self, client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_service_validity, client_to_tgs_session_key):
        tgt_content = f"{client_name},{client_ip},{timestamp},{ticket_granting_service_name},{ticket_granting_service_validity},{client_to_tgs_session_key}"
        encrypted_ticket_granting_ticket = encrypt(self.ticket_granting_service_key, tgt_content)
        return encrypted_ticket_granting_ticket

    def parse_tgs_ticket(self, encrypted_ticket_granting_ticket):
        decrypted_tgt = decrypt(self.ticket_granting_service_key, encrypted_ticket_granting_ticket)
        client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_ticket_validity, client_to_tgs_session_key = decrypted_tgt.split(',')
        return client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_ticket_validity, client_to_tgs_session_key