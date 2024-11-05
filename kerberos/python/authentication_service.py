# as.py
import socket
from config import Config
from utils import generate_random_key
from authentication import Authentication
from authentication_service_storage import AuthenticationServiceStorage

def handle_as_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"Authentication Service Request received: {request}")
    
    # 生成随机的16个字符的字符串作为会话密钥
    client_to_ticket_granting_service_authenticator_key = generate_random_key()
    response = Authentication().handle_request(request, client_to_ticket_granting_service_authenticator_key, 
                                               AuthenticationServiceStorage().get_user_public_key, 
                                               AuthenticationServiceStorage().select_one_ticket_granting_service_and_public_key)
    if None == response:
        print("Authentication failed.")
        client_socket.close()
    
    print(f"Authentication Service Response: {response}")
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(Config.AS_ADDRESS)
    server.listen(5)
    print("AS listening on port 5000")

    while True:
        client_socket, addr = server.accept()
        handle_as_request(client_socket)

if __name__ == "__main__":
    main()