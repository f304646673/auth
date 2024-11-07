import time
import rsa
from utils import encrypt, decrypt

class BizServiceTicket:
    def __init__(self, server_key):
        self.server_key = server_key
    
    def generate_service_ticket(self, client_name, client_ip, server_ip, ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key):
        st_content = f"{client_name},{client_ip},{server_ip},{ticket_granting_service_to_client_timestamp},{biz_service_ticket_validity},{client_to_biz_service_authenticator_key}"
        encrypted_st = rsa.encrypt_rsa(self.server_key, st_content)
        return encrypted_st
    
    def parse_service_ticket(self, encrypted_st):
        decrypted_st = rsa.decrypt_rsa(self.server_key, encrypted_st)
        try:
            client_name, client_ip, server_ip, ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key = decrypted_st.split(',')
        except:
            print("Error: Invalid service ticket: ", decrypted_st)
            return None, None, None, None, None, None
        
        return client_name, client_ip, server_ip, ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key
        