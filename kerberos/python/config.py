# config.py
class Config:
    CLIENT_KEY = "client_secret_k1"  # 16 bytes
    SERVER_KEY = "server_secret_k1"  # 16 bytes
    CLIENT_TO_ticket_granting_service_SESSION_KEY = "c_2_t_secret_key"    # 16 bytes
    CLIENT_TO_BIZ_SERVICE_SESSION_KEY = "c_2_s_secret_key"    # 16 bytes
    ticket_granting_service_KEY = "ticket_granting_service_secret_key__"  # 16
    AS_NAME = "AS"
    ticket_granting_service_NAME = "ticket_granting_service"
    AS_ADDRESS = ("localhost", 5000)
    ticket_granting_service_ADDRESS = ("localhost", 5001)
    SERVER_ADDRESS = ("localhost", 5002)