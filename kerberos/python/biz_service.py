# biz_service.py
import time
import socket
from config import Config
from utils import decrypt
from biz_service_ticket import BizServiceTicket
from biz_service_storage import BizServiceStorage
from client_to_biz_service_authenticator import ClientToBizServiceAuthenticator
import base64

def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"Server received request: {request}")
    encrypted_biz_service_ticket_base64, encrypted_client_to_biz_service_authenticator = request.split(',')
    print(f"Service Ticket: {encrypted_biz_service_ticket_base64}, Authenticator: {encrypted_client_to_biz_service_authenticator}")

    storage = BizServiceStorage()
    # Decrypt Service Ticket
    encrypted_biz_service_ticket = base64.b64decode(encrypted_biz_service_ticket_base64)
    client_name_from_biz_service_ticket, client_ip_from_biz_service_ticket, server_ip_from_biz_service_ticket, \
        ticket_granting_service_to_client_timestamp_from_biz_service_ticket, biz_service_ticket_validity_from_biz_service_ticket, client_to_biz_service_authenticator_key \
            = BizServiceTicket(storage.get_private_key()).parse_service_ticket(encrypted_biz_service_ticket)

    # Decrypt Authenticator
    print(f'Client to Biz Service Authenticator Key: {client_to_biz_service_authenticator_key}')
    client_name_from_authenticator , client_ip_from_authenticator, ticket_granting_service_to_client_timestamp_from_authenticator, biz_service_ticket_validity_from_authenticator = \
        ClientToBizServiceAuthenticator(client_to_biz_service_authenticator_key).parse_authenticator(encrypted_client_to_biz_service_authenticator)

    if client_name_from_biz_service_ticket != client_name_from_authenticator \
            or client_ip_from_biz_service_ticket != client_ip_from_authenticator \
            or ticket_granting_service_to_client_timestamp_from_biz_service_ticket != ticket_granting_service_to_client_timestamp_from_authenticator\
            or biz_service_ticket_validity_from_biz_service_ticket != biz_service_ticket_validity_from_authenticator:
        print(f"Client ID: {client_name_from_biz_service_ticket}, Client IP: {client_ip_from_biz_service_ticket}, Timestamp: {ticket_granting_service_to_client_timestamp_from_biz_service_ticket}")
        print(f"Client ID: {client_name_from_authenticator}, Client IP: {client_ip_from_authenticator}, Timestamp: {ticket_granting_service_to_client_timestamp_from_authenticator}")
        response = "Authentication Failed"
        client_socket.send(response.encode('utf-8'))
        client_socket.close()
        return
    
    if int(biz_service_ticket_validity_from_biz_service_ticket) < int(time.time()):
        print("Service Ticket expired.")
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