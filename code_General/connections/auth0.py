"""
Generic Backend

Silvio Weging 2023

Contains: Services for oauth verification
"""
import logging, json, os

import requests, datetime

from authlib.integrations.django_client import OAuth
from django.conf import settings
from .redis import RedisConnection

logger = logging.getLogger("django_debug")
#######################################################
# load auth0 configuration
auth0Config = json.load(open(os.path.dirname(__file__)+"/../configs/auth0.json"))

#######################################################
class OAuthLazy(OAuth):
    lazy_fn = None
    lazy_fn_called = False

    #######################################################
    def __init__(self):
        super().__init__()

    #######################################################
    def __getattr__(self, item):
        if self.lazy_fn not in (None, False) and item not in ('shape', '__len__', ) and not self.lazy_fn_called:
            self.lazy_fn(self)
            self.lazy_fn_called = True
        return super().__getattr__(item)

    #######################################################
    def setLazyFn(self, fn):
        self.lazy_fn = fn

#######################################################
def auth0Register(instance):
    logger.debug('initialisiere auth0')
    instance.register(
        "auth0",
        client_id=settings.AUTH0_CLIENT_ID,
        client_secret=settings.AUTH0_CLIENT_SECRET,
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
    )

oauth_auth0 = OAuthLazy()
oauth_auth0.setLazyFn(auth0Register)


#######################################################
def authorizeToken(request):
    """
    Get information back from Auth0 and generate token.

    :param request: POST request
    :type request: HTTP POST
    :return: Token
    :rtype: Dictionary

    """
    return oauth_auth0.auth0.authorize_access_token(request)

#######################################################
def authorizeRedirect(request, callback):
    """
    Authorize redirection for callback

    :param request: GET request
    :type request: HTTP GET
    :param callback: Function
    :type callback: Function
    :return: URI
    :rtype: HTTP URI

    """

    return oauth_auth0.auth0.authorize_redirect(
        request, request.build_absolute_uri(callback)
    )

#######################################################################################
def auth0OrgaRegister(instance: OAuth):
    instance.register(
        "auth0Orga",
        client_id=settings.AUTH0_ORGA_CLIENT_ID,
        client_secret=settings.AUTH0_ORGA_CLIENT_SECRET,
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
    )
oauth_auth0_orga = OAuthLazy()
oauth_auth0_orga.setLazyFn(auth0OrgaRegister)

#######################################################
def authorizeTokenOrga(request):
    """
    Get information back from Auth0 and generate token.

    :param request: POST request
    :type request: HTTP POST
    :return: Token
    :rtype: Dictionary

    """
    return oauth_auth0_orga.auth0Orga.authorize_access_token(request)

#######################################################
def authorizeRedirectOrga(request, callback):
    """
    Authorize redirection for callback

    :param request: GET request
    :type request: HTTP GET
    :param callback: Function
    :type callback: Function
    :return: URI
    :rtype: HTTP URI

    """

    return oauth_auth0_orga.auth0Orga.authorize_redirect(
        request, request.build_absolute_uri(callback)
    )

#######################################################
class ManageAPIToken:
    """
    Manage oauth token class.
    """
    savedToken = {}
    accessTokenString = ""
    redisConn = RedisConnection()
    redisKey = "auth0_access_token"


    #######################################################
    def __getattr__(self, item):
        if item == "accessToken":
            self.getAccessToken()
            return self.accessTokenString
        else:
            raise AttributeError

    #######################################################
    def getAccessToken(self):
        """
        Get initial token. Made as a function to be callable from outside. 

        :return: Nothing
        :rtype: None

        """
        alreadySavedToken, exists = self.redisConn.retrieveContentJSON(self.redisKey)
        # check if token exists or has expired
        if not exists or "expires_at" not in self.savedToken or datetime.datetime.now() > datetime.datetime.strptime(self.savedToken["expires_at"],"%Y-%m-%d %H:%M:%S.%f"):
            # Configuration Values
            audience = f'https://{settings.AUTH0_DOMAIN}/{auth0Config["APIPaths"]["APIBasePath"]}/'

            # Get an Access Token from Auth0
            base_url = f"https://{settings.AUTH0_DOMAIN}"
            payload =  { 
                'grant_type': "client_credentials",
                'client_id': settings.AUTH0_API_CLIENT_ID,
                'client_secret': settings.AUTH0_API_CLIENT_SECRET,
                'audience': audience
            }
            response = requests.post(f'{base_url}/oauth/token', data=payload)
            oauth = response.json()
            self.accessTokenString = oauth.get('access_token')
            self.savedToken = oauth
            now = datetime.datetime.now()
            self.savedToken["expires_at"] = str(now + datetime.timedelta(seconds=oauth["expires_in"]))
            self.redisConn.addContentJSON(self.redisKey, {"accessToken": self.accessTokenString, "savedToken": self.savedToken})
        else:
            self.savedToken = alreadySavedToken["savedToken"]
            self.accessTokenString = alreadySavedToken["accessToken"]

#######################################################
apiToken = ManageAPIToken()

#######################################################
# def retrieveOrganizationName(org_id):
#     """
#     Ask Auth0 API for name of an organization

#     :param org_id: ID gained from oauth token
#     :type org_id: str
#     :return: Name of organization
#     :rtype: str

#     """
#     apiToken.checkIfExpired()

#     # Add the token to the Authorization header of the request
#     headers = {
#         'authorization': f'Bearer {apiToken.accessToken}',
#         'content-Type': 'application/json'
#     }

#     # Get all Applications using the token
#     base_url = f"https://{settings.AUTH0_DOMAIN}"
#     try:
#         res = requests.get(f'{base_url}/api/v2/organizations/{org_id}', headers=headers)
#     except requests.HTTPError as e:
#         print(f'HTTPError: {str(e.code)} {str(e.reason)}')
#     except requests.URLRequired as e:
#         print(f'URLRequired: {str(e.reason)}')
#     except requests.RequestException as e:
#         print(f'RequestException: {e}')
#     except Exception as e:
#         print(f'Generic Exception: {e}')
#     return res.json()["display_name"]