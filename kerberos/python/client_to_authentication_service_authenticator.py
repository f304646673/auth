class ClientToAuthenticationServiceAuthenticator:
    def __init__(self):
        pass
    
    def generate_authenticator(self, client_name, client_ip, timestamp):
        authenticator_content = f"{client_name},{client_ip},{timestamp}"
        return authenticator_content
    
    def parse_authenticator(self, authenticator_content):
        client_name, client_ip, timestamp = authenticator_content.split(',')
        return client_name, client_ip, timestamp