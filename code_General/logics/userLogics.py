"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for the users
"""
import logging, numpy, requests, types, json, enum, datetime, re

from django.conf import settings
from django.utils import timezone

from ..connections.postgresql import pgProfiles
from ..connections import auth0
from ..definitions import *
from ..utilities import basics, crypto, signals
from ..utilities.basics import checkIfNestedKeyExists, handleTooManyRequestsError

from ..modelFiles.userModel import User

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForGetUserDetails(request):
    """
    Get the contractors for the service

    :return: The contractors
    :rtype: list
    """
    try:
        
        userObj = pgProfiles.ProfileManagementBase.getUser(request.session)
        userObj[SessionContent.usertype] = request.session[SessionContent.usertype]
        # show only the current organization
        if pgProfiles.ProfileManagementBase.checkIfUserIsInOrganization(request.session):
            organizationsOfUser = userObj[UserDescription.organizations].split(",")
            del userObj[UserDescription.organizations]
            currentOrganizationOfUser = pgProfiles.ProfileManagementBase.getOrganization(request.session)
            if isinstance(currentOrganizationOfUser, Exception):
                raise currentOrganizationOfUser
            for elem in organizationsOfUser:
                if elem == currentOrganizationOfUser[OrganizationDescription.hashedID]:
                    userObj["organization"] = elem
                    break
        else:
            del userObj[UserDescription.organizations] # users who logged in as users don't need the organization info leaked
         
        # parse addresses 
        if basics.checkIfNestedKeyExists(userObj, UserDescription.details, UserDetails.addresses):
            userObj[UserDescription.details][UserDetails.addresses] = list(userObj[UserDescription.details][UserDetails.addresses].values())
    
        
        return (userObj, None, 200)

    except Exception as e:
        loggerError.error(f"Error in {logicForGetUserDetails.__name__}: {str(e)}")
        return (None, e, 500)

##############################################
@staticmethod
def getUserKeyWOSC(session=None, uID=None): # deprecated
    """
    Retrieve User ID from Session without special characters

    :param session: session
    :type session: Dictionary
    :return: User key from database without stuff like | or ^
    :rtype: Str

    """
    userID = ""
    try:
        if session is not None:
            userID = session["user"]["userinfo"]["sub"]
        if uID is not None:
            userID = uID
        userID = re.sub(r"[^a-zA-Z0-9]", "", userID)
    except (Exception) as error:
        logger.error(f"Error getting user key WOSC: {str(error)}")

    return userID

##############################################
@staticmethod
def getUserKey(session):
    """
    Retrieve User ID from Session

    :param session: session
    :type session: Dictionary
    :return: User key session
    :rtype: Str

    """
    userID = ""
    try:
        userID = session["user"]["userinfo"]["sub"]
    except (Exception) as error:
        logger.error(f"Error getting user key: {str(error)}")

    return userID

##############################################
def logicForDeleteUser(request):
    # delete in database
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        userID = getUserKey(request.session)
        flag = pgProfiles.ProfileManagementUser.deleteUser(request.session)
        if flag is True:
            baseURL = f"https://{settings.AUTH0_DOMAIN}"
            headers = {
                'authorization': f'Bearer {auth0.apiToken.accessToken}',
                "customScopeKey": "permissions", 
                "customUserKey": "auth"
            }
            response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}', headers=headers) )
            if isinstance(response, Exception):
                loggerError.error(f"Error in {logicForDeleteUser.__name__}: {str(response)}")
                return (Exception("Failed to delete user"), 500)

            signals.signalDispatcher.userDeleted.send(None,userID=userID)
            logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.SELF},," + str(datetime.datetime.now()))
            return (None, 200)
        else:
            return (Exception("Failed to delete user"), 500)
    except Exception as e:
        loggerError.error(f"Error in {logicForDeleteUser.__name__}: {str(e)}")
        return (e, 500)

######################
def logicForAddUserTest(request):
    try:
        if request.session[SessionContent.PG_PROFILE_CLASS] == ProfileClasses.organization:
            orgaObj = pgProfiles.ProfileManagementBase.getOrganizationObject(request.session)
            if isinstance(orgaObj, Exception):
                raise orgaObj
            returnVal = pgProfiles.ProfileManagementOrganization.addUserIfNotExists(request.session, orgaObj)
            if isinstance(returnVal, Exception):
                raise returnVal
        else:
            returnVal = pgProfiles.ProfileManagementUser.addUserIfNotExists(request.session)
            if isinstance(returnVal, Exception):
                raise returnVal
        return (None, 200)
            
    except Exception as e:
        loggerError.error(f"Error in {logicForAddUserTest.__name__}: {str(e)}")
        return (e, 500)
    