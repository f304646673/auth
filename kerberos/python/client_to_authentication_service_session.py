class ClientToAuthenticationServiceSession:
    def __init__(self):
        pass
    
    def generate_session(self, client_id, client_ip, timestamp):
        session_content = f"{client_id},{client_ip},{timestamp}"
        return session_content
    
    def parse_session(self, session_content):
        client_id, client_ip, timestamp = session_content.split(',')
        return client_id, client_ip, timestamp