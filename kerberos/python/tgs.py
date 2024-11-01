# tgs.py
import socket
import time
from config import Config
from ticket_granting_ticket import TicketGrantingTicket
from utils import encrypt, decrypt

def handle_tgs_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"TGS Request received: {request}")
    encrypted_tgt, server_name, encrypted_request = request.split(',')
    
    if server_name != Config.SERVER_NAME:
        print(f"Server name mismatch. Expected: {Config.SERVER_NAME}, Actual: {server_name}")
        client_socket.send("Authentication Failed".encode('utf-8'))
        client_socket.close()
        return
    
    # Decrypt TGT
    client_id, client_ip, timestamp, tgs_name, tgt_validity, client_to_tgs_session_key = TicketGrantingTicket().parse_tgs_ticket(Config.TGS_KEY, encrypted_tgt)

    # Check if the timestamp is within the acceptable range (e.g., 5 minutes)
    current_time = int(time.time())
    if current_time > int(tgt_validity):
        print("Timestamp difference is greater than 5 minutes. Authentication failed.")
        client_socket.send("Authentication Failed".encode('utf-8'))
        return
    
    decrypted_request = decrypt(client_to_tgs_session_key, encrypted_request)
    client_id_from_part2, client_ip_from_part2, timestamp_from_part2 = decrypted_request.split(',')
    
    if client_id != client_id_from_part2 or client_ip != client_ip_from_part2 or timestamp != timestamp_from_part2:
        print(f"Client ID: {client_id}, Client IP: {client_ip}, Timestamp: {timestamp}")
        print(f"Client ID: {client_id_from_part2}, Client IP: {client_ip_from_part2}, Timestamp: {timestamp_from_part2}")
        client_socket.send("Authentication Failed".encode('utf-8'))
        client_socket.close()
        return
    
    st_timestamp = str(int(time.time()) + 60 * 10)

    # Generate Service Ticket
    encrypted_service_ticket = TicketGrantingTicket().generate_service_ticket(Config.SERVER_KEY, client_id, client_ip, Config.SERVER_NAME, timestamp, st_timestamp, Config.CLIENT_TO_SERVER_SESSION_KEY)
    
    session_content = f"{timestamp},{st_timestamp},{Config.CLIENT_TO_SERVER_SESSION_KEY}"
    encrypted_session = encrypt(Config.CLIENT_TO_TGS_SESSION_KEY, session_content)
    print("session_key:", Config.CLIENT_TO_TGS_SESSION_KEY)

    response = f'{encrypted_service_ticket},{encrypted_session}'
    print(f"TGS Response: {response}")
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(Config.TGS_ADDRESS)
    server.listen(5)
    print("TGS listening on port 5001")

    while True:
        client_socket, addr = server.accept()
        handle_tgs_request(client_socket)

if __name__ == "__main__":
    main()