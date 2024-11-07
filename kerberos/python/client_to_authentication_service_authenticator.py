class ClientToAuthenticationServiceAuthenticator:
    def __init__(self):
        pass
    
    def generate_authenticator(self, client_name, client_ip, client_to_authentication_service_timestamp):
        authenticator_content = f"{client_name},{client_ip},{client_to_authentication_service_timestamp}"
        return authenticator_content
    
    def parse_authenticator(self, authenticator_content):
        try:
            client_name, client_ip, client_to_authentication_service_timestamp = authenticator_content.split(',')
        except:
            print("Error: Invalid authenticator: ", authenticator_content)
            return None, None, None
        
        return client_name, client_ip, client_to_authentication_service_timestamp