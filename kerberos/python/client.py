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
from ticket_granting_service_to_client_session import TicketGrantingServiceToClientSession

def access_authentication_service(client_name, client_ip, timestamp):
    # Request ticket_granting_service_ticket from AS
    as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_socket.connect(Config.AS_ADDRESS)
    
    request = ClientToAuthenticationServiceSession().generate_session(client_name, client_ip, timestamp)
    as_socket.send(request.encode('utf-8'))
    response = as_socket.recv(1024).decode('utf-8')
    
    as_socket.close()
    print(f"Received ticket_granting_service_ticket response: {response}")
    
    return Authentication(Config.CLIENT_KEY).parse_response(response)

def access_ticket_granting_service(ticket_granting_service_ticket, client_name, client_to_tgs_session_key, server_ip, client_ip):
    # Create Authenticator
    timestamp = str(int(time.time()))
    session = ClientToTicketGrantingServiceSession(client_to_tgs_session_key).generate_session(client_name, client_ip, timestamp)

    # Request Service Ticket from TGS
    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_socket.connect(Config.TGS_ADDRESS)
    
    tgs_request = f"{ticket_granting_service_ticket},{server_ip},{session}"
    tgs_socket.send(tgs_request.encode('utf-8'))
    response = tgs_socket.recv(1024).decode('utf-8')
    
    tgs_socket.close()
    print(f"Received Service Ticket response: {response}")
    
    try:
        encrypted_biz_service_ticket, encrypted_response = response.split(',')
    except:
        print("Error parsing response from TGS.Response: ", response)
        return None, None, None
    
    decrypted_response = decrypt(client_to_tgs_session_key, encrypted_response)
    try:
        response_timestamp, st_validity, service_session_key = decrypted_response.split(',')
    except:
        print("Error parsing decrypted response.Response: ", decrypted_response)
        return None, None, None
    
    return encrypted_biz_service_ticket, service_session_key, st_validity
    

def access_biz_service(biz_service_ticket, service_session_key, client_name, client_ip, st_validity):
    # Create Authenticator
    timestamp = str(int(time.time()))
    session = ClientToBizServiceSession(service_session_key).generate_session(client_name, client_ip, timestamp, st_validity)

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
    client_name = "client1"
    client_ip = "192.168.1.100"  # Replace with actual client IP
    timestamp = str(int(time.time()))

    # Step 1: Request ticket_granting_service_ticket from AS
    encrypted_ticket_granting_service_ticket, timestamp, client_to_tgs_session_key = access_authentication_service(client_name, client_ip, timestamp)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    current_time = int(time.time())
    if int(timestamp) < current_time:
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        return

    # Step 2: Request Service Ticket from TGS
    encrypted_biz_service_ticket, service_session_key, st_validity = access_ticket_granting_service(encrypted_ticket_granting_service_ticket, client_name, client_to_tgs_session_key, Config.server_ip, client_ip)
   
    # Step 3: Access the service
    server_response = access_biz_service(encrypted_biz_service_ticket, service_session_key, client_name, client_ip, st_validity)
    print(f"Final Server response: {server_response}")

if __name__ == "__main__":
    main()