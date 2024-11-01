# server.py
import socket
from config import Config
from utils import decrypt
from biz_service_ticket import BizServiceTicket
from client_to_biz_service_session import ClientToBizServiceSession

def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"Server received request: {request}")
    encrypted_service_ticket, encrypted_session = request.split(',')
    print(f"Service Ticket: {encrypted_service_ticket}, Authenticator: {encrypted_session}")

    # Decrypt Service Ticket
    client_name_from_biz_service_ticket, client_ip_from_biz_service_ticket, server_ip_from_biz_service_ticket, \
        timestamp_from_biz_service_ticket, st_timestamp_from_biz_service_ticket, client_to_biz_service_session_key \
            = BizServiceTicket(Config.SERVER_KEY).parse_tgs_ticket(encrypted_service_ticket)

    # Decrypt Authenticator
    client_name_from_session , client_ip_from_session, timestamp_from_session, st_timestamp_from_authenticator = \
        ClientToBizServiceSession(client_to_biz_service_session_key).parse_session(encrypted_session)

    if client_name_from_biz_service_ticket != client_name_from_session \
            or client_ip_from_biz_service_ticket != client_ip_from_session \
            or timestamp_from_biz_service_ticket != timestamp_from_session:
        print(f"Client ID: {client_name_from_biz_service_ticket}, Client IP: {client_ip_from_biz_service_ticket}, Timestamp: {timestamp_from_biz_service_ticket}")
        print(f"Client ID: {client_name_from_session}, Client IP: {client_ip_from_session}, Timestamp: {timestamp_from_session}")
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