import time
from config import Config
from ticket_granting_service_ticket import TicketGrantingServiceTicket
from utils import encrypt, decrypt
from client_to_authentication_service_session import ClientToAuthenticationServiceSession
from authentication_service_to_client_session import AuthenticationServiceToClientSession

class Authentication:
        
    def __init__(self, client_key, ct_session_key = None, tsg_name = None, expires = 60 * 60):
        self.client_key = client_key
        self.ct_session_key = ct_session_key
        self.tsg_name = tsg_name
        self.expires = expires
        
    # Handle the request from the client
    def handle_request(self, request):
        try:
            client_id, client_ip, timestamp =  ClientToAuthenticationServiceSession().parse_session(request)
        except:
            print("Error parsing request from client.Request: ", request)
            return None
        
        # Set TGT validity period (e.g., 1 hour)
        tgt_validity = int(time.time()) + self.expires
        
        # Generate Ticket Granting Ticket (TGT)
        encrypted_tgt = TicketGrantingServiceTicket(Config.TGS_KEY).generate_tgs_ticket(
            client_id, client_ip, timestamp, self.tsg_name, tgt_validity, self.ct_session_key)
        
        # Generate Session Context
        encrypted_session = AuthenticationServiceToClientSession(self.client_key).generate_session(
            timestamp, self.tsg_name, tgt_validity, self.ct_session_key)
        
        response = f"{encrypted_tgt},{encrypted_session}"
        return response
        
    # Parse the response from the server
    def parse_response(self, response):
        encrypted_tgt, encrypted_session = response.split(',')

        timestamp, tgs_name, tgt_validity, ct_session_key = AuthenticationServiceToClientSession(self.client_key).parse_session(encrypted_session)
        print(f'Parsed encrypted_session: {timestamp}, {tgs_name}, {tgt_validity}, {ct_session_key}')

        # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
        current_time = int(time.time())
        if int(timestamp) < current_time:
            print("Timestamp difference is greater than 5 minutes. Authentication failed.")
            return None, None, None
        
        return encrypted_tgt, timestamp, ct_session_key


        
        
        