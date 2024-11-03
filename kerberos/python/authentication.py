import time
from config import Config
from ticket_granting_service_ticket import TicketGrantingServiceTicket
from utils import encrypt, decrypt
from client_to_authentication_service_session import ClientToAuthenticationServiceSession
from authentication_service_to_client_session import AuthenticationServiceToClientSession
from authentication_service_storage import AuthenticationServiceStorage
from client_storage import ClientStorage
import base64

class Authentication:
        
    # Handle the request from the client
    @staticmethod
    def handle_request(request, client_to_ticket_granting_service_session_key, expires = 30):
        try:
            client_name, client_ip, timestamp =  ClientToAuthenticationServiceSession().parse_session(request)
        except:
            print("Error parsing request from client.Request: ", request)
            return None
        
        storage = AuthenticationServiceStorage()
        
        user_public_key = storage.get_user_public_key(client_name)
        if user_public_key is None:
            print("User not found.")
            return None
        
        ticket_granting_service_ticket_validity = int(time.time()) + expires
        
        ticket_granting_service_name, ticket_granting_service_public_key = storage.select_one_ticket_granting_service_and_public_key()
        
        # Generate Ticket Granting Ticket (ticket_granting_service_ticket)
        encrypted_ticket_granting_service_ticket = TicketGrantingServiceTicket(ticket_granting_service_public_key).generate_ticket_granting_service_ticket(
            client_name, client_ip, timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key)
        
        encrypted_ticket_granting_service_ticket_base64 = base64.b64encode(encrypted_ticket_granting_service_ticket).decode('utf-8')
        
        # Generate Session Context
        encrypted_session = AuthenticationServiceToClientSession(user_public_key).generate_session(
            timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key)
        
        encrypted_session_base64 = base64.b64encode(encrypted_session).decode('utf-8')
        
        response = f"{encrypted_ticket_granting_service_ticket_base64},{encrypted_session_base64}"
        return response
        
    # Parse the response from the server
    @staticmethod
    def parse_response(response):
        private_key = ClientStorage().get_private_key()
        
        encrypted_ticket_granting_service_ticket_base64, encrypted_session_base64 = response.split(',')
        
        encrypted_ticket_granting_service_ticket = base64.b64decode(encrypted_ticket_granting_service_ticket_base64)
        encrypted_session = base64.b64decode(encrypted_session_base64)

        print(f'Parsed encrypted_session: {encrypted_session}')
        print(f'Parsed private_key: {private_key}')
        
        timestamp, ticket_granting_service_name, ticket_granting_service_ticket_validity, client_to_ticket_granting_service_session_key \
            = AuthenticationServiceToClientSession(private_key).parse_session(encrypted_session)
        print(f'Parsed encrypted_session: {timestamp}, {ticket_granting_service_name}, {ticket_granting_service_ticket_validity}, {client_to_ticket_granting_service_session_key}')

        # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
        current_time = int(time.time())
        if int(timestamp) < current_time:
            print("Timestamp difference is greater than 5 minutes. Authentication failed.")
            return None, None, None
        
        return encrypted_ticket_granting_service_ticket_base64, timestamp, client_to_ticket_granting_service_session_key


        
        
        