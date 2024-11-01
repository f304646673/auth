import time
from config import Config
import ticket_granting_ticket
from utils import encrypt, decrypt

class Authentication:
        
    def __init__(self, client_key, ct_session_key = None, tsg_name = None, tgt_period = 60 * 60):
        self.client_key = client_key
        self.ct_session_key = ct_session_key
        self.tsg_name = tsg_name
        
    def generate_request(self, client_id, client_ip, timestamp):
        return f"{client_id},{client_ip},{timestamp}"
        
    def handle_request(self, request):
        print(f"AS Request received: {request}")
        
        try:
            client_id, client_ip, timestamp = request.split(',')
        except:
            print("Error parsing request from client.Request: ", request)
            return None
        
        # Set TGT validity period (e.g., 1 hour)
        tgt_validity = int(time.time()) + 3600
        
        # Generate Ticket Granting Ticket (TGT)
        encrypted_tgt = ticket_granting_ticket.TicketGrantingTicket().generate_tgs_ticket(
            Config.TGS_KEY, client_id, client_ip, timestamp, self.tsg_name, tgt_validity, self.ct_session_key)
        
        # Generate Session Context
        encrypted_session = Authentication.Session(self.client_key).generate_encrypted_session(
            timestamp, self.tsg_name, tgt_validity, self.ct_session_key)
        
        response = f"{encrypted_tgt},{encrypted_session}"
        return response
        
    def parse_request(self, response):
        encrypted_tgt, encrypted_session = response.split(',')

        # Decrypt the second part of the response using the client key
        timestamp, tgs_name, tgt_validity, ct_session_key = Authentication.Session(self.client_key).decrypt_session(encrypted_session)
        print(f"Decrypted session: tgs_name={tgs_name}, tgt_validity={tgt_validity}, timestamp={timestamp}, ct_session_key={ct_session_key}")

        # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
        current_time = int(time.time())
        if int(timestamp) < current_time:
            print("Timestamp difference is greater than 5 minutes. Authentication failed.")
            return None, None, None
        
        return encrypted_tgt, timestamp, ct_session_key
        
    class Session:
        def __init__(self, client_key):
            self.client_key = client_key
            
        def generate_encrypted_session(self, timestamp, tgs_name, tgt_validity, ct_session_key):
            return encrypt(self.client_key, f"{timestamp},{tgs_name},{tgt_validity},{ct_session_key}")
        
        def decrypt_session(self, encrypted_session):
            session = decrypt(self.client_key, encrypted_session)
            try:
                timestamp, tgs_name, tgt_validity, ct_session_key = session.split(',')
            except:
                print("Error parsing session. Session: ", session)
                return None, None, None, None
            return timestamp, tgs_name, tgt_validity, ct_session_key


        
        
        