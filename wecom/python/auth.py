# auth.py
import requests
import time
import hashlib
from flask import request
from config import Config

class WeChatAuth:
    @staticmethod
    def get_authorize_url():
        params = {
            "appid": Config.WECHAT_CORP_ID,
            "redirect_uri": Config.WECHAT_REDIRECT_URI,
            "response_type": "code",
            "scope": "snsapi_base",
            "state": "STATE#wechat_redirect"
        }
        url = Config.WECHAT_AUTH_URL + "?" + "&".join([f"{k}={v}" for k, v in params.items()])
        return url

    @staticmethod
    def get_access_token():
        params = {
            "corpid": Config.WECHAT_CORP_ID,
            "corpsecret": Config.WECHAT_CORP_SECRET
        }
        response = requests.get(Config.WECHAT_TOKEN_URL, params=params)
        response_data = response.json()
        return response_data.get("access_token")

    @staticmethod
    def get_user_info(code):
        access_token = WeChatAuth.get_access_token()
        params = {
            "access_token": access_token,
            "code": code
        }
        response = requests.get(Config.WECHAT_USER_INFO_URL, params=params)
        return response.json()

    @staticmethod
    def get_jsapi_ticket():
        access_token = WeChatAuth.get_access_token()
        url = f"https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token={access_token}"
        response = requests.get(url)
        return response.json().get("ticket")

    @staticmethod
    def get_jsapi_config(url):
        ticket = WeChatAuth.get_jsapi_ticket()
        nonceStr = "randomString"
        timestamp = int(time.time())
        string1 = f"jsapi_ticket={ticket}&noncestr={nonceStr}&timestamp={timestamp}&url={url}"
        signature = hashlib.sha1(string1.encode('utf-8')).hexdigest()
        return {
            "appId": Config.WECHAT_CORP_ID,
            "timestamp": timestamp,
            "nonceStr": nonceStr,
            "signature": signature
        }