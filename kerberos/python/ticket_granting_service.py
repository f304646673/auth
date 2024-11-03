# ticket_granting_service.py
import socket
import time
import random
import string
from config import Config
from biz_service_ticket import BizServiceTicket
from ticket_granting_service_ticket import TicketGrantingServiceTicket
from ticket_granting_service_to_client_session import TicketGrantingServiceToClientSession
from client_to_authentication_service_session import ClientToAuthenticationServiceSession
from client_to_ticket_granting_service_session import ClientToTicketGrantingServiceSession
from ticket_granting_service_storage import TicketGrantingServiceStorage
from utils import encrypt, decrypt
import base64

def generate_random_key(length=16):
    """
    生成一个随机的16个字符的字符串
    """
    characters = string.ascii_letters + string.digits
    random_key = ''.join(random.choice(characters) for i in range(length))
    return random_key

def handle_ticket_granting_service_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"ticket_granting_service Request received: {request}")
    encrypted_ticket_granting_service_ticket_base64, server_ip, encrypted_session = request.split(',')
    
    encrypted_ticket_granting_service_ticket = base64.b64decode(encrypted_ticket_granting_service_ticket_base64)
    
    storage = TicketGrantingServiceStorage()
    bize_service_public_key = storage.get_biz_service_public_key(server_ip)
    if bize_service_public_key is None:
        print(f"Server name mismatch. Actual: {server_ip}")
        client_socket.send("Authentication Failed".encode('utf-8'))
        client_socket.close()
        return
    
    private_key = TicketGrantingServiceStorage().get_private_key()
    
    # Decrypt ticket_granting_service_ticket
    client_name_from_ticket_granting_service_ticket, client_ip_from_ticket_granting_service_ticket, \
        timestamp_from_ticket_granting_service_ticket, ticket_granting_service_name_from_ticket_granting_service_ticket, \
        ticket_granting_service_ticket_validity_from_ticket_granting_service_ticket, client_to_ticket_granting_service_session_key \
        = TicketGrantingServiceTicket(private_key).parse_ticket_granting_service_ticket(encrypted_ticket_granting_service_ticket)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    current_time = int(time.time())
    if current_time > int(ticket_granting_service_ticket_validity_from_ticket_granting_service_ticket):
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        client_socket.send("Authentication Failed".encode('utf-8'))
        return
    
    client_name_from_session, client_ip_from_session, timestamp_from_session \
        = ClientToTicketGrantingServiceSession(client_to_ticket_granting_service_session_key).parse_session(encrypted_session)
    
    if client_name_from_ticket_granting_service_ticket != client_name_from_session or client_ip_from_ticket_granting_service_ticket != client_ip_from_session or timestamp_from_ticket_granting_service_ticket != timestamp_from_session:
        print(f"Client ID: {client_name_from_ticket_granting_service_ticket}, Client IP: {client_ip_from_ticket_granting_service_ticket}, Timestamp: {timestamp_from_ticket_granting_service_ticket}")
        print(f"Client ID: {client_name_from_session}, Client IP: {client_ip_from_session}, Timestamp: {timestamp_from_session}")
        client_socket.send("Authentication Failed".encode('utf-8'))
        client_socket.close()
        return
    
    st_timestamp = str(int(time.time()) + 60 * 10)

    # Generate Service Ticket
    client_to_biz_service_session_key = generate_random_key()
    encrypted_biz_service_ticket = BizServiceTicket(storage.get_biz_service_public_key(server_ip)).generate_service_ticket(client_name_from_ticket_granting_service_ticket, client_ip_from_ticket_granting_service_ticket, 
                                                                                           server_ip, timestamp_from_ticket_granting_service_ticket, st_timestamp, 
                                                                                           client_to_biz_service_session_key)
    encrypted_biz_service_ticket_base64 = base64.b64encode(encrypted_biz_service_ticket).decode('utf-8')
    
    # Generate Session Context
    encrypted_session = TicketGrantingServiceToClientSession(client_to_ticket_granting_service_session_key).generate_session(timestamp_from_ticket_granting_service_ticket, st_timestamp, client_to_biz_service_session_key)
    print("session_key:", client_to_ticket_granting_service_session_key)
    
    print(f'encrypted_service_ticket: {encrypted_biz_service_ticket}, encrypted_session: {encrypted_session}')

    response = f'{encrypted_biz_service_ticket_base64},{encrypted_session}'
    print(f"ticket_granting_service Response: {response}")
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(Config.ticket_granting_service_ADDRESS)
    server.listen(5)
    print("ticket_granting_service listening on port 5001")

    while True:
        client_socket, addr = server.accept()
        handle_ticket_granting_service_request(client_socket)

if __name__ == "__main__":
    main()