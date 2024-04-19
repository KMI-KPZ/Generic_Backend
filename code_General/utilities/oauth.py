"""
Part of Semper-KI software

Thomas Skodawessely & Silvio Weging 2024

Contains: Oauth token management class
"""

import datetime
from authlib.integrations.requests_client import OAuth2Session

#######################################################
class ManageToken:
    """
    Manage oauth token class.
    """
    _token = None
    client : OAuth2Session = None
    client_id = None
    client_secret = None
    token_endpoint = None
    token_endpoint_auth_method = None

    def __init__(self, client_id, client_secret, token_endpoint, token_endpoint_auth_method) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.client = OAuth2Session(client_id, client_secret, token_endpoint=token_endpoint, token_endpoint_auth_method=token_endpoint_auth_method)


    #######################################################
    def __getattr__(self, item):
        if item == "token":
            if self._token is None:
                self.getAccessToken()
            return self._token
        else:
            raise AttributeError
    
    #######################################################
    def __del__(self):
        self.client.close()

    #######################################################
    def getAccessToken(self):
        """
        Get initial token. Made as a function to be callable from outside. 
        Reminder for me: It makes no sense to save this access token in redis because it expires much to quickly!
        """
        self._token = self.client.fetch_token(grant_type='client_credentials')
    
    #######################################################
    def checkIfExpired(self):
        """
        Check if token has expired and if so, refresh it. 
        """
        expirationTimeAT = str(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=self.token["expires_at"]))
        expirationTimeRT = str(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=self.token["expires_at"]-self.token["expires_in"]+self.token["refresh_expires_in"]))
        if datetime.datetime.now() > datetime.datetime.strptime(expirationTimeAT,"%Y-%m-%d %H:%M:%S+00:00"):
            # check if refresh token has expired as well
            if datetime.datetime.now() > datetime.datetime.strptime(expirationTimeRT,"%Y-%m-%d %H:%M:%S+00:00"):
                # it has, request new token
                self.getAccessToken()
            else:
                # it has not, ask for refresh token
                self._token = self.client.refresh_token(self.token_endpoint , refresh_token=self.token["refresh_token"])