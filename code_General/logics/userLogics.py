"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for the users
"""
import logging, numpy, requests, types, json, enum, datetime

from django.conf import settings
from django.utils import timezone

from ..connections.postgresql import pgProfiles
from ..connections import auth0
from ..definitions import *
from ..utilities import basics, handleTooManyRequestsError, checkIfNestedKeyExists, crypto, signals

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
    
        
        return userObj, None, 200

    except Exception as e:
        loggerError.error("Error in logicForGetUserDetails: %s" % e)
        return None, e, 500

##############################################
@staticmethod
def logicForUserUpdateContent(session, updates, userID=""):
    """
    Update user details.

    :param session: GET request session
    :type session: Dictionary
    :param updates: The user details to update
    :type updates: differs
    :param userID: The user ID who updates. If not given, the subID will be used	
    :type userID: str
    :return: If it worked or not
    :rtype: None | Exception

    """
    if userID == "":
        subID = session["user"]["userinfo"]["sub"]
    else:
        subID = userID
    updated = timezone.now()
    try:
        mocked = False
        if SessionContent.MOCKED_LOGIN in session and session[SessionContent.MOCKED_LOGIN] is True:
            mocked = True
        existingObj = User.objects.get(subID=subID)
        existingInfo = {UserDescription.name: existingObj.name, UserDescription.details: existingObj.details}
        for updateType in updates:
            details = updates[updateType]
            if updateType == UserUpdateType.displayName:
                assert isinstance(details, str), f"updateUser failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[UserDescription.name] = details
            elif updateType == UserUpdateType.email:
                assert isinstance(details, str), f"updateUser failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[UserDescription.details][UserDetails.email] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Accept": "application/json",
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"email": details})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{subID}', data=payload, headers=headers) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == UserUpdateType.address:
                assert isinstance(details, dict), f"updateUser failed because the wrong type for details was given: {type(details)} instead of dict"
                setToStandardAddress = details["standard"] # if the new address will be the standard address
                addressAlreadyExists = False
                newContentInDB = {}
                if UserDetails.addresses in existingInfo[UserDescription.details]: # add old content
                    newContentInDB = existingInfo[UserDescription.details][UserDetails.addresses] 
                    for key in newContentInDB:
                        if "id" in details and details["id"] == newContentInDB[key]["id"]:
                            addressAlreadyExists = True
                        if setToStandardAddress:
                            newContentInDB[key]["standard"] = False
                if addressAlreadyExists == False:
                    # add new content
                    idForNewAddress = crypto.generateURLFriendlyRandomString()
                    details["id"] = idForNewAddress
                else:
                    # overwrite existing entry
                    idForNewAddress = details["id"]
                newContentInDB[idForNewAddress] = details
                existingInfo[UserDescription.details][UserDetails.addresses] = newContentInDB
            elif updateType == UserUpdateType.locale:
                assert isinstance(details, str) and ("en" in details or "de" in details), f"updateUser failed because the wrong type for details was given: {type(details)} instead of str or the locale didn't contain de or en"
                existingInfo[UserDescription.details][UserDetails.locale] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Accept": "application/json",
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"user_metadata": {"language": details}})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{subID}', data=payload, headers=headers) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == UserUpdateType.notifications:
                assert isinstance(details, dict), f"updateUser failed because the wrong type for details was given: {type(details)} instead of dict"
                if ProfileClasses.user in details:
                    for notification in details[ProfileClasses.user]: 
                        if not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.user, notification) \
                            or not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.user, notification, UserNotificationTargets.email) \
                            or not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.user, notification, UserNotificationTargets.event):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.user][notification] = {UserNotificationTargets.email: True, UserNotificationTargets.event: True} 

                        if checkIfNestedKeyExists(details, ProfileClasses.user, notification, UserNotificationTargets.email):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.user][notification][UserNotificationTargets.email] = details[ProfileClasses.user][notification][UserNotificationTargets.email]
                        if checkIfNestedKeyExists(details, ProfileClasses.user, notification, UserNotificationTargets.event):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.user][notification][UserNotificationTargets.event] = details[ProfileClasses.user][notification][UserNotificationTargets.event]
                if ProfileClasses.organization in details:
                    for notification in details[ProfileClasses.organization]: 
                        if not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.organization, notification) \
                            or not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.email) \
                            or not checkIfNestedKeyExists(existingInfo, UserDescription.details, UserDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.organization][notification] = {UserNotificationTargets.email: True, UserNotificationTargets.event: True} 

                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.email):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.email] = details[ProfileClasses.organization][notification][UserNotificationTargets.email]
                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[UserDescription.details][UserDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.event] = details[ProfileClasses.organization][notification][UserNotificationTargets.event]
                
            else:
                raise Exception("updateType not defined")
        
        affected = User.objects.filter(subID=subID).update(details=existingInfo[UserDescription.details], name=existingInfo[UserDescription.name], updatedWhen=updated)
        return None
    except (Exception) as error:
        logger.error(f"Error updating user details: {str(error)}")
        return error
    
##############################################
@staticmethod
def logicForUserDeleteContent(session, updates, userID=""):
    """
    Delete certain user details.

    :param session: GET request session
    :type session: Dictionary
    :param updates: The user details to update
    :type updates: differs
    :param userID: The user ID to update. If not given, the subID will be used	
    :type userID: str
    :return: If it worked or not
    :rtype: None | Exception

    """
    try:
        if userID == "":
            subID = session["user"]["userinfo"]["sub"]
        else:
            subID = userID
        updated = timezone.now()
    
        existingObj = User.objects.get(subID=subID)
        existingInfo = {UserDescription.name: existingObj.name, UserDescription.details: existingObj.details}
        for updateType in updates:
            details = updates[updateType]
            
            if updateType == UserUpdateType.address:
                assert isinstance(details, str), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of str"
                del existingInfo[UserDescription.details][UserDetails.addresses][details]
            else:
                raise Exception("updateType not defined")
        
        affected = User.objects.filter(subID=subID).update(details=existingInfo[UserDescription.details], name=existingInfo[UserDescription.name], updatedWhen=updated)
        return None
    except (Exception) as error:
        logger.error(f"Error updating user details: {str(error)}")
        return error

##############################################
def logicForDeleteUser(request):
    # delete in database
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        userID = pgProfiles.ProfileManagementBase.getUserKey(request.session)
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
                loggerError.error(f"Error deleting user: {str(response)}")
                return (Exception("Failed to delete user"), 500)

            signals.signalDispatcher.userDeleted.send(None,userID=userID)
            logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.SELF},," + str(datetime.datetime.now()))
            return (None, 200)
        else:
            return (Exception("Failed to delete user"), 500)
    except Exception as e:
        loggerError.error(f"Error deleting user: {str(e)}")
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
        loggerError.error(f"Error deleting user: {str(e)}")
        return (e, 500)
    