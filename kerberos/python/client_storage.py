class ClientStorage:
    def __init__(self) -> None:
        self.client_private_keys = \
"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAooS2Wv0+lE3WvadoqXpvRQftiecerPIZxjx1PhbT60+5fN6S
Kep4X/KtyEHE6ZB6T9VW1t2q78HUq/ujMrzqHGmHnDQRhq621CnusKw3OwAG5hSF
ikY7vjfFMDjwpKt0+DGhDrX5Pe8cAgFsyswjjpvhHpdd4u4Invj4QQY6JJPjJeCq
Jx6o37MjEIVDVU/oNXzpElQEYbZmBFwDIJBB/BR0zS6InhwTxZh5vrELWt4HWSTJ
KuAg+5dZbMqs0I6nMDi+JspkOZtnGIU704V+0ocDEA0Ar0vQQm1CceAnJlerDuAv
KaXbsyj5wFmmYf4vvh5S2nTS1N06Zrv0gTgkSQIDAQABAoIBAAb/e/KzEOzF5UdJ
XCJgGUZ5rurPPuznh+CXXd0MkpeBWVVdKCIR7JkFFCKZYmdER2AEqbaa2O92Azhc
n4xhwhrzGFnLjC2mfEzqeVK2N7Kcr69cltt7ZrssH5uR+Bq/H0xIpszBXTgjgas8
cHjTDXzojWsJzYsmAM0Hn3j9UaedfPdZyQCeiceOz5wedLHLJFBstaJlnV0Ar/F5
HcbQw+9L78weOV1ptYbRyVTdpnmH3vy9SE/WIV9Cx9nL0DWaZumsWiUKx2VsoM4S
TaxdDohvQpgjWXAfIXIskMBkS0hLH+Y2DTEP1FTCQ1ODr6rK13pxO0vyNrR3BQGA
MXEImuECgYEAuY0W0qI34zlEdIJQzOWuvPLwX8ERMdVHSW7huFxDwRuigRFuR36v
qTw/bwZreti3iNmGoaRIn6vuYFxyP9V35RkVFGanNBZN1bP3wtMeXYhV8pTAadU6
mr3dQ5dkJDPWzMo2zTElR8sRIHWCrA++ETbRZ0D9IF1JGyg0Huj7fPUCgYEA4Djs
pQtiSnMInIJn6lklmrLDJFdQ/vF8ohpe9sUoJifCaJIFEFm/PsN33x33PvA/fBWj
I507C/rq6cVx01x2U2kIGhyVcz/JGiD1ozbykdLUE/vCA5PNNiAMX6aueqOLMT4i
c6ZnDQywPl60lH6nsTCxdQSOf5rNI7ucEbf7tYUCgYBhiUrf+inKpcXYQNBchLfv
1vyIOSLiwSwx67l3gfiTwAUSN6lyp6OLIIJvyD4jW1xO8ZmVypfqZyRtPutHptzZ
bu/nw3ZNKRRNK8cngHbLz+juFUd32oBt6zQuXZxkc2OMTxezkQv5y0L7fwnrjHLq
9Zfp4P2uT5soTV/oh6v7KQKBgQDXJigEUkEVWP4JV6QonTPVFfTjmRkyGDvUO+Ol
fBcDTaFgv8Q2JTe6HMuX/uPws4znHsf0c3lmDHV+rSOEgTNU4/KPQ6Av/yOTe87X
tvDY9ejj5+4JirgdWHEnEwRWzzjPnmRmfmRhhCxVHIDAACwefK+6rg2h6cMvp2Sh
J95SFQKBgGBa4fzEiGS2vcekB315rnrgCMeSSqcr8dcTUCbMKMdKtK2dNLxXlaLR
+MVdaGQLBI9+StmQfl7gA1l7gtpb3JjMeczhYiSXeX0fvDw7B+W7c+lmkn246P7H
Uh31tRl8w9mUu6oKoaWNF0ARpPnJ5FuzBdst6F0SjTsKdz5+WNJx
-----END RSA PRIVATE KEY-----"""
    
    def get_private_key(self):
        return self.client_private_keys
    