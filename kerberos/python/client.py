# client.py
import socket
import time
import base64
import rsa
from config import Config
from utils import encrypt, decrypt
from authentication import Authentication
from client_to_biz_service_authenticator import ClientToBizServiceAuthenticator
from client_to_authentication_service_authenticator import ClientToAuthenticationServiceAuthenticator
from authentication_service_to_client_authenticator import AuthenticationServiceToClientAuthenticator
from client_to_ticket_granting_service_authenticator import ClientToTicketGrantingServiceAuthenticator
from ticket_granting_service_to_client_authenticator import TicketGrantingServiceToClientAuthenticator

def access_authentication_service(client_name, client_ip, client_to_authentication_service_timestamp):
    # Request ticket_granting_service_ticket from AS
    as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_socket.connect(Config.AS_ADDRESS)
    
    request = ClientToAuthenticationServiceAuthenticator().generate_authenticator(
        client_name, client_ip, client_to_authentication_service_timestamp)
    
    as_socket.send(request.encode('utf-8'))
    response = as_socket.recv(1024).decode('utf-8')
    
    as_socket.close()
    print(f"Received ticket_granting_service_ticket response: {response}")
    
    return Authentication().parse_response(response)

def access_ticket_granting_service(
    encrypted_ticket_granting_service_ticket_base64, client_name, 
    client_to_ticket_granting_service_authenticator_key, server_ip, client_ip):
    # Create Authenticator
    client_to_ticket_granting_service_timestamp = str(int(time.time()))
    client_to_ticket_granting_service_authenticator = ClientToTicketGrantingServiceAuthenticator(client_to_ticket_granting_service_authenticator_key).generate_authenticator(client_name, client_ip, client_to_ticket_granting_service_timestamp)

    # Request Service Ticket from ticket_granting_service
    ticket_granting_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ticket_granting_service_socket.connect(Config.ticket_granting_service_ADDRESS)
    
    ticket_granting_service_request = f"{encrypted_ticket_granting_service_ticket_base64},{server_ip},{client_to_ticket_granting_service_authenticator}"
    ticket_granting_service_socket.send(ticket_granting_service_request.encode('utf-8'))
    response = ticket_granting_service_socket.recv(1024).decode('utf-8')
    
    ticket_granting_service_socket.close()
    print(f"Received Service Ticket response: {response}")
    
    try:
        encrypted_biz_service_ticket_base64, encrypted_authenticator = response.split(',')
    except:
        print("Error parsing response from ticket_granting_service.Response: ", response)
        return None, None, None
    
    
    print(f"client_to_ticket_granting_service_authenticator_key: {client_to_ticket_granting_service_authenticator_key}, encrypted_response: {encrypted_authenticator}")
    try:
        ticket_granting_service_to_client_timestamp, biz_service_ticket_validity, client_to_biz_service_authenticator_key =  TicketGrantingServiceToClientAuthenticator(client_to_ticket_granting_service_authenticator_key).parse_authenticator(encrypted_authenticator)
    except:
        print("Error parsing decrypted encrypted_authenticator: ", encrypted_authenticator)
        return None, None, None
    
    return encrypted_biz_service_ticket_base64, client_to_biz_service_authenticator_key, biz_service_ticket_validity
    

def access_biz_service(encrypted_biz_service_ticket_base64, client_to_biz_service_authenticator_key, client_name, client_ip, biz_service_ticket_validity):
    # Create Authenticator
    client_to_biz_service_timestamp = str(int(time.time()))
    encrypted_client_to_biz_service_authenticator = ClientToBizServiceAuthenticator(client_to_biz_service_authenticator_key).generate_authenticator(client_name, client_ip, client_to_biz_service_timestamp, biz_service_ticket_validity)

    # Send Service Ticket and Authenticator to Server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(Config.SERVER_ADDRESS)
    
    server_request = f"{encrypted_biz_service_ticket_base64},{encrypted_client_to_biz_service_authenticator}"
    server_socket.send(server_request.encode('utf-8'))
    response = server_socket.recv(1024).decode('utf-8')
    
    server_socket.close()
    print(f"Received Server response: {response}")
    return response

def main():
    client_name = "alice"
    client_ip = "192.168.1.100"  # Replace with actual client IP
    client_to_authentication_service_timestamp = int(time.time())

    # Step 1: Request ticket_granting_service_ticket from AS
    encrypted_ticket_granting_service_ticket_base64, \
    authentication_service_to_client_timestamp, \
    client_to_ticket_granting_service_authenticator_key = \
        access_authentication_service(client_name, client_ip, client_to_authentication_service_timestamp)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    if int(authentication_service_to_client_timestamp) - client_to_authentication_service_timestamp > 60 * 5:
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        return

    # Step 2: Request Service Ticket from ticket_granting_service
    biz_service_ip = "172.0.0.2"
    encrypted_biz_service_ticket_base64, client_to_biz_service_authenticator_key, biz_service_ticket_validity = \
        access_ticket_granting_service(encrypted_ticket_granting_service_ticket_base64, client_name, client_to_ticket_granting_service_authenticator_key, biz_service_ip, client_ip)
   
    print(f"encrypted_biz_service_ticket: {encrypted_biz_service_ticket_base64}, client_to_biz_service_authenticator_key: {client_to_biz_service_authenticator_key}, biz_service_ticket_validity: {biz_service_ticket_validity}")
    # Step 3: Access the service
    server_response = access_biz_service(encrypted_biz_service_ticket_base64, client_to_biz_service_authenticator_key, client_name, client_ip, biz_service_ticket_validity)
    print(f"Final Server response: {server_response}")

if __name__ == "__main__":
    main()