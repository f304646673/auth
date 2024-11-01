# as.py
import socket
import time
from config import Config
from utils import encrypt

def handle_as_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"AS Request received: {request}")
    client_id, client_ip, timestamp = request.split(',')
    
    # Set TGT validity period (e.g., 1 hour)
    tgt_validity = int(time.time()) + 3600
    
    # Generate Ticket Granting Ticket (TGT)
    tgt_content = f"{client_id},{client_ip},{timestamp},{Config.TGS_NAME},{tgt_validity},{Config.CT_SK}"
    encrypted_tgt = encrypt(Config.CT_SK, tgt_content)

    # Generate Session Context
    session_content = f"{timestamp},{Config.TGS_NAME},{tgt_validity},{Config.CT_SK}"
    encrypted_session = encrypt(Config.CLIENT_KEY, session_content)

    response = f"{encrypted_tgt},{encrypted_session}"
    print(f"AS Response: {response}")
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(Config.AS_ADDRESS)
    server.listen(5)
    print("AS listening on port 5000")

    while True:
        client_socket, addr = server.accept()
        handle_as_request(client_socket)

if __name__ == "__main__":
    main()