# server.py
import socket
from config import Config
from utils import decrypt
from biz_service_ticket import BizServiceTicket

def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"Server received request: {request}")
    encrypted_service_ticket, encrypted_session = request.split(',')
    print(f"Service Ticket: {encrypted_service_ticket}, Authenticator: {encrypted_session}")

    # Decrypt Service Ticket
    client_id, client_ip, server_name, timestamp, st_timestamp, cs_sk = BizServiceTicket(Config.SERVER_KEY).parse_tgs_ticket(encrypted_service_ticket)

    # Decrypt Authenticator
    decrypted_authenticator = decrypt(cs_sk, encrypted_session)
    client_id_from_authenticator , client_ip_from_authenticator, timestamp_from_authenticator, st_timestamp_from_authenticator = decrypted_authenticator.split(',')

    if client_id != client_id_from_authenticator or client_ip != client_ip_from_authenticator or timestamp != timestamp_from_authenticator:
        print(f"Client ID: {client_id}, Client IP: {client_ip}, Timestamp: {timestamp}")
        print(f"Client ID: {client_id_from_authenticator}, Client IP: {client_ip_from_authenticator}, Timestamp: {timestamp_from_authenticator}")
        response = "Authentication Failed"
        client_socket.send(response.encode('utf-8'))
        client_socket.close()
        return
    
    response = "Authentication Successful"

    print(f"Server response: {response}")
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(Config.SERVER_ADDRESS)
    server.listen(5)
    print("Server listening on port 5002")

    while True:
        client_socket, addr = server.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    main()