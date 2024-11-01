# config.py
class Config:
    CLIENT_KEY = "client_secret_k1"  # 16 bytes
    SERVER_KEY = "server_secret_k1"  # 16 bytes
    CT_SK = "kdc_secret_key_t"    # 16 bytes
    CS_SK = "kdc_secret_key_s"    # 16 bytes
    AS_NAME = "AS"
    TGS_NAME = "TGS"
    SERVER_NAME = "BizServer"
    AS_ADDRESS = ("localhost", 5000)
    TGS_ADDRESS = ("localhost", 5001)
    SERVER_ADDRESS = ("localhost", 5002)