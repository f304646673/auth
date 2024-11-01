# config.py
class Config:
    CLIENT_KEY = "client_secret_k1"  # 16 bytes
    SERVER_KEY = "server_secret_k1"  # 16 bytes
    CLIENT_TO_TGS_SESSION_KEY = "c_2_t_secret_key"    # 16 bytes
    CLIENT_TO_SERVER_SESSION_KEY = "c_2_s_secret_key"    # 16 bytes
    TGS_KEY = "tgs_secret_key__"  # 16
    AS_NAME = "AS"
    TGS_NAME = "TGS"
    SERVER_NAME = "BizServer"
    AS_ADDRESS = ("localhost", 5000)
    TGS_ADDRESS = ("localhost", 5001)
    SERVER_ADDRESS = ("localhost", 5002)