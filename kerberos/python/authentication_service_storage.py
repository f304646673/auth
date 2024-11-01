class AuthenticationServiceStorage:
    
    def __init__(self) -> None:
        self.user_name_to_public_key = {"alice": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAooS2Wv0+lE3WvadoqXpv\nRQftiecerPIZxjx1PhbT60+5fN6SKep4X/KtyEHE6ZB6T9VW1t2q78HUq/ujMrzq\nHGmHnDQRhq621CnusKw3OwAG5hSFikY7vjfFMDjwpKt0+DGhDrX5Pe8cAgFsyswj\njpvhHpdd4u4Invj4QQY6JJPjJeCqJx6o37MjEIVDVU/oNXzpElQEYbZmBFwDIJBB\n/BR0zS6InhwTxZh5vrELWt4HWSTJKuAg+5dZbMqs0I6nMDi+JspkOZtnGIU704V+\n0ocDEA0Ar0vQQm1CceAnJlerDuAvKaXbsyj5wFmmYf4vvh5S2nTS1N06Zrv0gTgk\nSQIDAQAB\n-----END PUBLIC KEY-----"}
        self.ticket_granting_service_to_public_key = {"ticket_granting_service": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt16rg6ibrntgDfPPsOqt\nBMWA40+5m6FKWMqUV6cchyp7hmqawa62BWwBl5Qx9sRR8ihAaZXFDMLuLEQnZ04x\noLcXmw1twhoOoxOSCGZHnv1kXNogstiH4ZoU7Qxl8EyBrnHYBAly1glX4HLg+Q9B\nIJMXCbZ4CiIJ49D5lHpFnRiBSKHPDAuZESBrTk1hpoIEM2eCbAvyPnidMPIZhyVh\n13C6ytcSYDllYyRRXgZOdSoKi88hpY9mpwQRf8pDYljqXhxVytdBBBVenCLQQ7Rj\n17177sLjXnyqNEUUCF2W1DggRVOye/iTMqtwapyn9abdOWdOkdxpFE4GHNFfQzim\nIQIDAQAB\n-----END PUBLIC KEY-----"}
        
    # Get the public key of the user
    def get_user_public_key(self, user_name):
        return self.user_name_to_public_key.get(user_name)
    
    def select_one_ticket_granting_service_and_public_key(self):
        # Select the first ticket granting service and its public key
        ticket_granting_service_name, ticket_granting_service_public_key = next(iter(self.ticket_granting_service_to_public_key.items()))
        return ticket_granting_service_name, ticket_granting_service_public_key