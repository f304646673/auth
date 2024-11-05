import time
from config import Config
from ticket_granting_service_ticket import TicketGrantingServiceTicket
from utils import encrypt, decrypt
from client_to_authentication_service_authenticator import ClientToAuthenticationServiceAuthenticator
from authentication_service_to_client_authenticator import AuthenticationServiceToClientAuthenticator
from authentication_service_storage import AuthenticationServiceStorage
from client_storage import ClientStorage
import base64

class Authentication:
        
    # Handle the request from the client
    @staticmethod
    def handle_request(request, client_to_ticket_granting_service_authenticator_key, expires = 30):
        try:
            client_name, client_ip, client_to_authentication_service_timestamp =  ClientToAuthenticationServiceAuthenticator().parse_authenticator(request)
        except:
            print("Error parsing request from client.Request: ", request)
            return None
        
        storage = AuthenticationServiceStorage()
        
        user_public_key = storage.get_user_public_key(client_name)
        if user_public_key is None:
            print("User not found.")
            return None
        
        authentication_service_to_client_timestamp = int(time.time())
        ticket_granting_service_ticket_validity = authentication_service_to_client_timestamp + expires
        
        ticket_granting_service_name, ticket_granting_service_public_key = storage.select_one_ticket_granting_service_and_public_key()
        
        # Generate Ticket Granting Ticket (ticket_granting_service_ticket)
        encrypted_ticket_granting_service_ticket = TicketGrantingServiceTicket(ticket_granting_service_public_key).generate_ticket_granting_service_ticket(
            client_name, client_ip, authentication_service_to_client_timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_authenticator_key)
        
        encrypted_ticket_granting_service_ticket_base64 = base64.b64encode(encrypted_ticket_granting_service_ticket).decode('utf-8')
        
        # Generate Authenticator Context
        encrypted_authenticator = AuthenticationServiceToClientAuthenticator(user_public_key).generate_authenticator(
            authentication_service_to_client_timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_authenticator_key)
        
        encrypted_authenticator_base64 = base64.b64encode(encrypted_authenticator).decode('utf-8')
        
        response = f"{encrypted_ticket_granting_service_ticket_base64},{encrypted_authenticator_base64}"
        return response
        
    # Parse the response from the server
    @staticmethod
    def parse_response(response):
        private_key = ClientStorage().get_private_key()
        
        encrypted_ticket_granting_service_ticket_base64, encrypted_authenticator_base64 = response.split(',')
        
        encrypted_ticket_granting_service_ticket = base64.b64decode(encrypted_ticket_granting_service_ticket_base64)
        encrypted_authenticator = base64.b64decode(encrypted_authenticator_base64)

        print(f'Parsed encrypted_authenticator: {encrypted_authenticator}')
        print(f'Parsed private_key: {private_key}')
        
        authentication_service_to_client_timestamp, ticket_granting_service_name,\
            ticket_granting_service_ticket_validity, client_to_ticket_granting_service_authenticator_key \
            = AuthenticationServiceToClientAuthenticator(private_key).parse_authenticator(encrypted_authenticator)
        print(f'Parsed encrypted_authenticator: {authentication_service_to_client_timestamp}, {ticket_granting_service_name}, {ticket_granting_service_ticket_validity}, {client_to_ticket_granting_service_authenticator_key}')

        # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
        current_time = int(time.time())
        if int(authentication_service_to_client_timestamp) < current_time:
            print("Timestamp difference is greater than 5 minutes. Authentication failed.")
            return None, None, None
        
        return encrypted_ticket_granting_service_ticket_base64, authentication_service_to_client_timestamp, client_to_ticket_granting_service_authenticator_key


        
        
        