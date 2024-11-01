# server.py
import socket
from config import Config
from utils import decrypt

def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"Server received request: {request}")
    encrypted_service_ticket, encrypted_server_request_part2 = request.split(',')
    print(f"Service Ticket: {encrypted_service_ticket}, Authenticator: {encrypted_server_request_part2}")

    # Decrypt Service Ticket
    decrypted_ticket = decrypt(Config.SERVER_KEY, encrypted_service_ticket)
    client_id, client_ip, server_name, timestamp, st_timestamp, cs_sk = decrypted_ticket.split(',')

    # Decrypt Authenticator
    decrypted_authenticator = decrypt(cs_sk, encrypted_server_request_part2)
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