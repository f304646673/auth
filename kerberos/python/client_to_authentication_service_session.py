class ClientToAuthenticationServiceSession:
    def __init__(self):
        pass
    
    def generate_session(self, client_name, client_ip, timestamp):
        session_content = f"{client_name},{client_ip},{timestamp}"
        return session_content
    
    def parse_session(self, session_content):
        client_name, client_ip, timestamp = session_content.split(',')
        return client_name, client_ip, timestamp