# client.py
import socket
import time
from config import Config
from utils import encrypt, decrypt
from authentication import Authentication
from client_to_biz_service_session import ClientToBizServiceSession
from client_to_authentication_service_session import ClientToAuthenticationServiceSession
from authentication_service_to_client_session import AuthenticationServiceToClientSession
from client_to_ticket_granting_service_session import ClientToTicketGrantingServiceSession

def request_ticket_granting_service_ticket(client_id, client_ip, timestamp):
    # Request ticket_granting_service_ticket from AS
    as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_socket.connect(Config.AS_ADDRESS)
    
    request = ClientToAuthenticationServiceSession().generate_session(client_id, client_ip, timestamp)
    as_socket.send(request.encode('utf-8'))
    response = as_socket.recv(1024).decode('utf-8')
    
    as_socket.close()
    print(f"Received ticket_granting_service_ticket response: {response}")
    
    return Authentication(Config.CLIENT_KEY).parse_response(response)

def request_service_ticket(ticket_granting_service_ticket, client_id, session_key, server_name, client_ip):
    # Create Authenticator
    timestamp = str(int(time.time()))
    session = ClientToTicketGrantingServiceSession(session_key).generate_session(client_id, client_ip, timestamp)

    # Request Service Ticket from TGS
    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_socket.connect(Config.TGS_ADDRESS)
    
    tgs_request = f"{ticket_granting_service_ticket},{server_name},{session}"
    tgs_socket.send(tgs_request.encode('utf-8'))
    response = tgs_socket.recv(1024).decode('utf-8')
    
    tgs_socket.close()
    print(f"Received Service Ticket response: {response}")
    return response

def access_biz_service(biz_service_ticket, service_session_key, client_id, client_ip, st_validity):
    # Create Authenticator
    timestamp = str(int(time.time()))
    session = ClientToBizServiceSession(service_session_key).generate_session(client_id, client_ip, timestamp, st_validity)

    # Send Service Ticket and Authenticator to Server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(Config.SERVER_ADDRESS)
    
    server_request = f"{biz_service_ticket},{session}"
    server_socket.send(server_request.encode('utf-8'))
    response = server_socket.recv(1024).decode('utf-8')
    
    server_socket.close()
    print(f"Received Server response: {response}")
    return response

def main():
    client_id = "client1"
    client_ip = "192.168.1.100"  # Replace with actual client IP
    timestamp = str(int(time.time()))

    # Step 1: Request ticket_granting_service_ticket from AS
    encrypted_ticket_granting_service_ticket, timestamp, ct_session_key = request_ticket_granting_service_ticket(client_id, client_ip, timestamp)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    current_time = int(time.time())
    if int(timestamp) < current_time:
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        return

    # Step 2: Request Service Ticket from TGS
    service_ticket_response = request_service_ticket(encrypted_ticket_granting_service_ticket, client_id, ct_session_key, Config.SERVER_NAME, client_ip)
    print(f"Received Service Ticket response: {service_ticket_response}")
    biz_service_ticket, encrypted_response = service_ticket_response.split(',')

    # Decrypt the second part of the response using the session key
    decrypted_response = decrypt(ct_session_key, encrypted_response)
    response_timestamp, st_validity, service_session_key = decrypted_response.split(',')
    print(f"Decrypted response: service_session_key={service_session_key}, response_timestamp={response_timestamp}, st_validity={st_validity}")

    # Step 3: Access the service
    server_response = access_biz_service(biz_service_ticket, service_session_key, client_id, client_ip, st_validity)
    print(f"Final Server response: {server_response}")

if __name__ == "__main__":
    main()