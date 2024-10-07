"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Calls to the API Token model
"""
from .pgProfiles import ProfileManagementBase, ProfileManagementUser, ProfileManagementOrganization
from ...modelFiles.apiTokenModel import APITokenDescription, APIToken

from logging import getLogger
logger = getLogger("errors")

##################################################
def createAPIToken(session) -> str | Exception:
    """
    Generate an API Token for User/Organization if there is none yet

    :param session: The session
    :type sessioN: Dict-like
    :return: The token string or Exception
    :rtype: str | Exception
    
    """
    try:
        isInOrga = ProfileManagementBase.checkIfUserIsInOrganization(session)
        if isInOrga:
            orgaObj = ProfileManagementOrganization.getOrganizationObject(session)
            tokenObj = APIToken.objects.get_or_create(organization=orgaObj)
            return tokenObj[0].token
        else:
            userObj = ProfileManagementUser.getUserObj(session)
            tokenObj = APIToken.objects.get_or_create(user=userObj)
            return tokenObj[0].token
    except (Exception) as error:
        logger.error(f"Error generating or fetching API token: {str(error)}")
        return error

##################################################
def checkAPIToken(token:str) -> bool | Exception:
    """
    Check if API Token is legit

    :param token: The API token
    :type token: str
    :return: if legit or not
    :rtype: bool
    
    """
    try:
        APIToken.objects.get(token=token)
        return True
    except (Exception) as error:
        return False