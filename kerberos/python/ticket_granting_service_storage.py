class TicketGrantingServiceStorage:
    def __init__(self):
        self.biz_service_to_public_key = {"172.0.0.2": \
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtbvpNwwPaoriXqOWHS9i
stH1l8Bhcu9anbG/CqCWKIwfCDyAxg2VUlyfMJbVoAdte9EFSyEIMlcyHn+pZGEb
EczcyRzOiD51/A3kfGbDjkl2VayCA9cYfTenq4Fs9iHD+a1pDmDiCCcgy1Mx8MWR
Vt7L/GdlOvNxscTWTKoW8nKUv08fy9XppsTFwZOWKWBJmnbqxIM80hiGxyoVfO4A
KI2liaTT5j/YGVZNKYxE2++mwBKydnstfNPtDu5IpCfDAwkL81pvDPCkuEa8O4NA
oYZ+nefA80qZjscd4aX/UxWuS0wxyPQWdSRq84WX33r6s3Ap20JO2Vk5zUS1hie5
DQIDAQAB
-----END PUBLIC KEY-----"""}
        
        self.private_key = \
"""-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAt16rg6ibrntgDfPPsOqtBMWA40+5m6FKWMqUV6cchyp7hmqa
wa62BWwBl5Qx9sRR8ihAaZXFDMLuLEQnZ04xoLcXmw1twhoOoxOSCGZHnv1kXNog
stiH4ZoU7Qxl8EyBrnHYBAly1glX4HLg+Q9BIJMXCbZ4CiIJ49D5lHpFnRiBSKHP
DAuZESBrTk1hpoIEM2eCbAvyPnidMPIZhyVh13C6ytcSYDllYyRRXgZOdSoKi88h
pY9mpwQRf8pDYljqXhxVytdBBBVenCLQQ7Rj17177sLjXnyqNEUUCF2W1DggRVOy
e/iTMqtwapyn9abdOWdOkdxpFE4GHNFfQzimIQIDAQABAoIBAA6z8rLzdqswhZDM
1UEJah7dMsLXOknYLpDMyoT2N29/mKi8HMVNq9bmtIB5z6FKl8r/zv1gVszZhvUp
8FJkVs6dC7GhK6UyB20sRSvy/ohpJy5aR5+rhMayPv4MXdKdIdNR2ckmFE0E8gTD
VVZnEpjo7mKXHMwsM0iO8aol/TW1teJg9YCdnoT2s2tRixuEAb3bPNk6n+UEJvsn
WL65FzQSnNHyOwe8+QgFCFZouMDlOZr1GXBPNdsugSmqnKB8avZNyRS8+B2++V1/
r1vrgRb6fa9RKQu79em60mFXLkt0WEg8AOrpSkKsNQBcv7MV/ayKVuNFt79LHLNy
VyBNICkCgYEAzb4v1d9uLFeJ195qN4xEvvoOXRaPbK6GykmN+OMA6h/DHOE7aKrc
32cZvwsmyuxFYktRPnMfLlarcYT9/k1CFkJsLZxO+WBfb4yL+dHzo5EwttTELz3Z
z/1gb7rtF/aHp3EHOW5RdqB/4xT5Ja17Y9tjObfQL6gvOf3RvGmK27kCgYEA5Clq
UxPGk97v4qfPUOcGxj0Oy1G/q/AlRM6Ktb9Q60oySiv7Z41/tUIiqCCVGnWYqlBA
+OxKkOwsWVtGJQjC/VxBjrX/r3ZmV/k7XeuYCSBI/CLpWqiLDBEQvLna+84yXQt0
2HHYxRb/aZK3m4yvxqFfRsZZUUZSsWvm4/7w4akCgYEAtmLf4vezoilj7/KiNGXr
V2UysIDcWhsJMHAuJDGQUPwhKgvcb3fwXzb1ku8ez4rOI0njVroVLS31w6eCxhnU
+Qie/3vuYpF1aNyuBaOCGUEPbzSESeDJouDZyZJqtfB85wmCvv21x7SWSkcAas80
cBw/BR6WtnigjQceE6l4SDkCgYEAxIzs/F533eDalE3tqYsr6dClkv98d9jrsief
lMwYIGmNgxn6fI2H65TqmB1hdSbC+k0ie43K+qeJ2PxpI/Q1Td+Q1ijw962uorCg
tNsE4S+/z/0fO6sgBagZ3Arbm7pY5pC8+sywabDTHJZ4t3Zt4lYX5rduMDa9e/wx
Lk3sIukCgYEAlX0tvmpmw0NyxjvTSKEuSUidoGpbAA6Rh479mKOrbao/RgSud7Qg
rbhF1CxwTgLK4adMyQCdPRXoui4yfJt2qK/6mO/Pm7DZmfnmcZ/CO67JtgXiiHeW
UtUki8vsLtu8lGlh5t6ANRMwc6x0V0QNof+OtrZoqs0nXVAsdw0MN/I=
-----END RSA PRIVATE KEY-----"""
    
    def get_private_key(self):
        return self.private_key
    
    def get_biz_service_public_key(self, biz_service_name):
        return self.biz_service_to_public_key.get(biz_service_name)