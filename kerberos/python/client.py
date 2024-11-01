# client.py
import socket
import time
from config import Config
from utils import encrypt, decrypt
import authentication

def request_tgt(client_id, client_ip, timestamp):
    # Request TGT from AS
    as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_socket.connect(Config.AS_ADDRESS)
    
    auth = authentication.Authentication(Config.CLIENT_KEY)
    request = auth.generate_request(client_id, client_ip, timestamp)

    as_socket.send(request.encode('utf-8'))
    response = as_socket.recv(1024).decode('utf-8')
    as_socket.close()
    print(f"Received TGT response: {response}")
    
    return auth.parse_request(response)

def request_service_ticket(tgt, client_id, session_key, server_name, client_ip):
    # Create Authenticator
    timestamp = str(int(time.time()))
    authenticator = encrypt(session_key, f"{client_id},{client_ip},{str(timestamp)}")

    # Request Service Ticket from TGS
    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_socket.connect(Config.TGS_ADDRESS)
    tgs_request = f"{tgt},{server_name},{authenticator}"
    tgs_socket.send(tgs_request.encode('utf-8'))
    response = tgs_socket.recv(1024).decode('utf-8')
    tgs_socket.close()
    print(f"Received Service Ticket response: {response}")
    return response

def access_service(service_ticket, service_session_key, client_id, client_ip, st_validity):
    # Create Authenticator
    timestamp = str(int(time.time()))
    authenticator = encrypt(service_session_key, f"{client_id},{client_ip},{timestamp},{st_validity}")

    # Send Service Ticket and Authenticator to Server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(Config.SERVER_ADDRESS)
    server_request = f"{service_ticket},{authenticator}"
    server_socket.send(server_request.encode('utf-8'))
    response = server_socket.recv(1024).decode('utf-8')
    server_socket.close()
    print(f"Received Server response: {response}")
    return response

def main():
    client_id = "client1"
    client_ip = "192.168.1.100"  # Replace with actual client IP
    timestamp = str(int(time.time()))

    # Step 1: Request TGT from AS
    encrypted_tgt, timestamp, ct_session_key = request_tgt(client_id, client_ip, timestamp)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    current_time = int(time.time())
    if int(timestamp) < current_time:
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        return

    # Step 2: Request Service Ticket from TGS
    service_ticket_response = request_service_ticket(encrypted_tgt, client_id, ct_session_key, Config.SERVER_NAME, client_ip)
    print(f"Received Service Ticket response: {service_ticket_response}")
    service_ticket, encrypted_response = service_ticket_response.split(',')

    # Decrypt the second part of the response using the session key
    decrypted_response = decrypt(ct_session_key, encrypted_response)
    response_timestamp, st_validity, service_session_key = decrypted_response.split(',')
    print(f"Decrypted response: service_session_key={service_session_key}, response_timestamp={response_timestamp}, st_validity={st_validity}")

    # Step 3: Access the service
    server_response = access_service(service_ticket, service_session_key, client_id, client_ip, st_validity)
    print(f"Final Server response: {server_response}")

if __name__ == "__main__":
    main()