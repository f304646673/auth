# ticket_granting_service.py
import socket
import time
from config import Config
from biz_service_ticket import BizServiceTicket
from ticket_granting_service_ticket import TicketGrantingServiceTicket
from ticket_granting_service_to_client_session import TicketGrantingServiceToClientSession
from client_to_authentication_service_session import ClientToAuthenticationServiceSession
from client_to_ticket_granting_service_session import ClientToTicketGrantingServiceSession
from utils import encrypt, decrypt

def handle_ticket_granting_service_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"ticket_granting_service Request received: {request}")
    encrypted_ticket_granting_service_ticket, server_ip, encrypted_session = request.split(',')
    
    if server_ip != Config.server_ip:
        print(f"Server name mismatch. Expected: {Config.server_ip}, Actual: {server_ip}")
        client_socket.send("Authentication Failed".encode('utf-8'))
        client_socket.close()
        return
    
    # Decrypt ticket_granting_service_ticket
    client_name_from_ticket_granting_service_ticket, client_ip_from_ticket_granting_service_ticket, \
        timestamp_from_ticket_granting_service_ticket, ticket_granting_service_name_from_ticket_granting_service_ticket, \
        ticket_granting_service_ticket_validity_from_ticket_granting_service_ticket, client_to_ticket_granting_service_session_key \
        = TicketGrantingServiceTicket(Config.ticket_granting_service_KEY).parse_ticket_granting_service_ticket(encrypted_ticket_granting_service_ticket)

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
    encrypted_service_ticket = BizServiceTicket(Config.SERVER_KEY).generate_service_ticket(client_name_from_ticket_granting_service_ticket, client_ip_from_ticket_granting_service_ticket, Config.server_ip, timestamp_from_ticket_granting_service_ticket, st_timestamp, Config.CLIENT_TO_BIZ_SERVICE_SESSION_KEY)
    
    # Generate Session Context
    encrypted_session = TicketGrantingServiceToClientSession(Config.CLIENT_TO_ticket_granting_service_SESSION_KEY).generate_session(timestamp_from_ticket_granting_service_ticket, st_timestamp, Config.CLIENT_TO_BIZ_SERVICE_SESSION_KEY)
    print("session_key:", Config.CLIENT_TO_ticket_granting_service_SESSION_KEY)

    response = f'{encrypted_service_ticket},{encrypted_session}'
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