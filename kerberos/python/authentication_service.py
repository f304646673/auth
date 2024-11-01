# as.py
import socket
import time
import random
import string
from config import Config
from authentication import Authentication

def generate_random_key(length=16):
    """
    生成一个随机的16个字符的字符串
    """
    characters = string.ascii_letters + string.digits
    random_key = ''.join(random.choice(characters) for i in range(length))
    return random_key

def handle_as_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    print(f"AS Request received: {request}")
    
    # 生成随机的16个字符的字符串作为会话密钥
    client_to_ticket_granting_service_session_key = generate_random_key()
    response = Authentication().handle_request(request, client_to_ticket_granting_service_session_key)
    
    print(f"AS Response: {response}")
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