# config.py
import os
from dotenv import load_dotenv, find_dotenv

class Config:
    WECHAT_CORP_ID = ""
    WECHAT_CORP_SECRET = ""
    WECHAT_REDIRECT_URI = ""
    WECHAT_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize"
    WECHAT_TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    WECHAT_USER_INFO_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
    
    def __init__(self) -> None:
        load_dotenv(find_dotenv())
        self.WECHAT_CORP_ID = os.getenv("WECHAT_CORP_ID")
        self.WECHAT_CORP_SECRET = os.getenv("WECHAT_CORP_SECRET")
        self.WECHAT_REDIRECT_URI = os.getenv("WECHAT_REDIRECT_URI")