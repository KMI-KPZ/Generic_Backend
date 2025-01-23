"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Calls to the API Token model
"""
from django.core.exceptions import ObjectDoesNotExist

from .pgProfiles import ProfileManagementBase, ProfileManagementUser, ProfileManagementOrganization
from ...utilities.basics import manualCheckifAdmin
from ...modelFiles.apiTokenModel import APITokenDescription, APIToken

from logging import getLogger
logger = getLogger("errors")

##################################################
def checkIfAPITokenExists(session) -> str | Exception:
    """
    Checks if there already is a token and if so, return it

    :param session: The session
    :type sessioN: Dict-like
    :return: Token if it exists, empty string if not
    :rtype: str | Exception
    
    """
    try:
        isInOrga = ProfileManagementBase.checkIfUserIsInOrganization(session)
        if isInOrga:
            orgaObj = ProfileManagementOrganization.getOrganizationObject(session)
            token = APIToken.objects.get(organization=orgaObj)
            return token.token
        else:
            userObj = ProfileManagementUser.getUserObj(session)
            token = APIToken.objects.get(user=userObj)
            return token.token
    except (ObjectDoesNotExist) as error:
        return ""
    except (Exception) as error:
        return error

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
        adminOrNot = manualCheckifAdmin(session)
        if isInOrga:
            orgaObj = ProfileManagementOrganization.getOrganizationObject(session)
            tokenObj = APIToken.objects.get_or_create(organization=orgaObj, admin=adminOrNot)
            return tokenObj[0].token
        else:
            userObj = ProfileManagementUser.getUserObj(session)
            tokenObj = APIToken.objects.get_or_create(user=userObj, admin=adminOrNot)
            return tokenObj[0].token
    except (Exception) as error:
        logger.error(f"Error generating or fetching API token: {str(error)}")
        return error

##################################################
def checkAPITokenAndRetrieveUserObject(token:str):
    """
    Check if API Token is legit and if so, return either the user or the orga

    :param token: The API token
    :type token: str
    :return: (False, None, False) if there is nothing, (False, User, False) if a user is associated with that token, else (True, Organization, False). The last one is only true if the user/orga is an admin.
    :rtype: (bool, None | User | Organization, bool)
    
    """
    try:
        tokenObj = APIToken.objects.get(token=token)
        if tokenObj.user != None:
            return (False, tokenObj.user, tokenObj.admin)
        elif tokenObj.organization != None:
            return (True, tokenObj.organization, tokenObj.admin)
        
        return (False, None, False)
    except (Exception) as error:
        return (False, None, False)
    
##################################################
def deleteAPIToken(token:str):
    """
    Deletes the API token for that user/orga

    :param token: The API token
    :type token: str
    :return: None or Exception if it didn't work
    :rtype: None | Exception
    """
    try:
        APIToken.objects.filter(token=token).delete()
    except (Exception) as error:
        return error