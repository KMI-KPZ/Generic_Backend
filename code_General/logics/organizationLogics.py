"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for the organizations
"""
import logging, numpy
import datetime

from ..connections.postgresql import pgProfiles, pgEvents
from ..definitions import *

from ..utilities import basics

from django.conf import settings

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

import types, json, enum, re, requests

from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

from ..connections import auth0
from ..utilities.basics import handleTooManyRequestsError
from ..modelFiles.organizationModel import Organization
from ..modelFiles.userModel import User

from ..utilities import crypto, signals
from ..utilities.basics import checkIfNestedKeyExists
from ..definitions import *

from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def sendEventViaWebsocket(orgID, baseURL, baseHeader, eventName, args):
    """
    Send events to the respective websockets.

    :param orgID: ID of that organization
    :type orgID: str
    :param baseURL: stuff for Auth0
    :type baseURL: str
    :param baseHeader: stuff for Auth0
    :type baseHeader: str
    :param eventName: stuff for frontend
    :type eventName: str
    :param args: other arguments
    :type args: str
    :return: True or exception
    :rtype: Bool or exception
    """
    try:
        channel_layer = get_channel_layer()
        if eventName == "assignRole" or eventName == "removeRole":
            userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(userSubID=args)
            if userHashedID != "":
                groupName = userHashedID[:80]
                eventData = {
                        EventsDescriptionGeneric.primaryID: orgID,
                        EventsDescriptionGeneric.reason: "roleChanged",
                        EventsDescriptionGeneric.content: "roleChanged"
                }
                event = pgEvents.createEventEntry(userHashedID, EventsDescriptionGeneric.orgaEvent, eventData, True)
                async_to_sync(channel_layer.group_send)(groupName, {
                    "type": "sendMessageJSON",
                    "dict": event,
                })

        elif eventName == "addPermissionsToRole" or eventName == "editRole":
            # get list of all members, retrieve the user ids and filter for those affected
            response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=baseHeader) )
            if isinstance(response, Exception):
                raise response
            responseDict = response
            for user in responseDict:
                userID = user["user_id"]
                
                resp = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=baseHeader) )
                if isinstance(resp, Exception):
                    raise resp    
                for elem in resp:
                    if elem["id"] == args:
                        userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(userSubID=userID)
                        if userHashedID != "":
                            groupName = userHashedID[:80]
                            eventData = {
                                    EventsDescriptionGeneric.primaryID: orgID,
                                    EventsDescriptionGeneric.reason: "roleChanged",
                                    EventsDescriptionGeneric.content: "roleChanged"
                            }
                            event = pgEvents.createEventEntry(userHashedID, EventsDescriptionGeneric.orgaEvent, eventData, True)
                            async_to_sync(channel_layer.group_send)(groupName, {
                                "type": "sendMessageJSON",
                                "dict": event,
                            })

        elif eventName == "deleteUserFromOrganization":
            userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(userSubID=args)
            if userHashedID != "":
                groupName = userHashedID[:80]
                eventData = {
                        EventsDescriptionGeneric.primaryID: orgID,
                        EventsDescriptionGeneric.reason: "userDeleted",
                        EventsDescriptionGeneric.content: "userDeleted"
                }
                event = pgEvents.createEventEntry(userHashedID, EventsDescriptionGeneric.orgaEvent, eventData, True)

                async_to_sync(channel_layer.group_send)(groupName, {
                    "type": "sendMessageJSON",
                    "dict": event,
                })

        return True
    except Exception as e:
        return e
    
##############################################
@staticmethod
def logicsForOrganizationsUpdateContent(session, updates, orgaID=""):
    """
    Update user details and more.
    :param session: GET request session
    :type session: Dictionary
    :param updates: The orga details to update
    :type updates: differs
    :param orgaID: The orga ID who updates. If not given, the org_id will be used	
    :type orgaID: str
    :return: Worked or not
    :rtype: None | Exception

    """
    if orgaID == "":
        orgID = session["user"]["userinfo"]["org_id"]
    else:
        orgID = orgaID
    updated = timezone.now()
    try:
        existingObj = Organization.objects.get(subID=orgID)
        existingInfo = {OrganizationDescription.details: existingObj.details, OrganizationDescription.supportedServices: existingObj.supportedServices, OrganizationDescription.name: existingObj.name}
            
        mocked = False
        if SessionContent.MOCKED_LOGIN in session and session[SessionContent.MOCKED_LOGIN] is True:
            mocked = True
            
        sendSignals = {}

        for updateType in updates:
            details = updates[updateType]
            if updateType == OrganizationUpdateType.supportedServices:
                assert isinstance(details, list), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of list"
                supportedServices = []
                for supportedService in details:
                    supportedServices.append(supportedService)
                supportedServices.extend(existingInfo[OrganizationDescription.supportedServices])

                sendSignals[OrganizationDescription.supportedServices] = supportedServices
                existingInfo[OrganizationDescription.supportedServices] = supportedServices
            elif updateType == OrganizationUpdateType.services:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                existingInfo[OrganizationDescription.details][OrganizationDetails.services] = details
            elif updateType == OrganizationUpdateType.address:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                setToStandardAddress = details["standard"] # if the new address will be the standard address
                addressAlreadyExists = False
                newContentInDB = {}
                if OrganizationDetails.addresses in existingInfo[OrganizationDescription.details]: # add old content
                    newContentInDB = existingInfo[OrganizationDescription.details][OrganizationDetails.addresses]
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
                existingInfo[OrganizationDescription.details][OrganizationDetails.addresses] = newContentInDB
            elif updateType == OrganizationUpdateType.displayName:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.name] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"display_name": details})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == OrganizationUpdateType.email:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.details][OrganizationDetails.email] = details
            elif updateType == OrganizationUpdateType.branding:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"branding": details})
                    #{
                        # "logo_url": "string",
                        # "colors": {
                        # "primary": "string",
                        # "page_background": "string"
                    # }
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
                    existingInfo[OrganizationDescription.details][OrganizationDetails.branding] = details
            elif updateType == OrganizationUpdateType.locale:
                assert isinstance(details, str) and ("de" in details or "en" in details), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str or locale string was wrong"
                existingInfo[OrganizationDescription.details][OrganizationDetails.locale] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"metadata": { "language": details}})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == OrganizationUpdateType.taxID:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.details][OrganizationDetails.taxID] = details
            elif updateType == OrganizationUpdateType.notifications:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                if ProfileClasses.organization in details:
                    for notification in details[ProfileClasses.organization]:   
                        if not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification) \
                            or not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.email) \
                            or not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification] = {UserNotificationTargets.email: True, UserNotificationTargets.event: True} 

                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.email):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.email] = details[ProfileClasses.organization][notification][UserNotificationTargets.email]
                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.event] = details[ProfileClasses.organization][notification][UserNotificationTargets.event]
                                
            elif updateType == OrganizationUpdateType.priorities:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                for key in details:
                    existingInfo[OrganizationDescription.details][OrganizationDetails.priorities][key] = details[key]
            else:
                raise Exception("updateType not defined")
                
        affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], updatedWhen=updated)
            
        if len(sendSignals) > 0:
            for key in sendSignals:
                match key:
                    case OrganizationDescription.supportedServices:
                        signals.signalDispatcher.orgaServiceDetails.send(None, orgaID=existingObj.hashedID, details=sendSignals[key])
            
        return None
    except (Exception) as error:
        logger.error(f"Error updating organization details: {str(error)}")
        return error

##############################################
@staticmethod
def logicsForOrganizationsDeleteContent(session, updates, orgaID=""):
    """
    Delete certain orga details.

    :param session: GET request session
    :type session: Dictionary
    :param updates: The orga details to update
    :type updates: differs
    :param orgaID: The orga ID to update. If not given, the subID will be used	
    :type orgaID: str
    :return: If it worked or not
    :rtype: None | Exception

    """
    if orgaID == "":
        orgID = session["user"]["userinfo"]["org_id"]
    else:
        orgID = orgaID
    updated = timezone.now()
    try:
        existingObj = Organization.objects.get(subID=orgID)
        existingInfo = {OrganizationDescription.details: existingObj.details, OrganizationDescription.supportedServices: existingObj.supportedServices, OrganizationDescription.name: existingObj.name}
        
        sendSignals = {}
        
        for updateType in updates:
            details = updates[updateType]
            
            if updateType == OrganizationUpdateType.address:
                assert isinstance(details, str), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of str"
                del existingInfo[OrganizationDescription.details][OrganizationDetails.addresses][details]
            elif updateType == OrganizationUpdateType.supportedServices:
                assert isinstance(details, list), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of list"
                # deletion not necessary because the array is set in the changes function without the not set services
                existingInfo[OrganizationDescription.supportedServices] = [elem for elem in existingInfo[OrganizationDescription.supportedServices] if elem not in details]
                sendSignals[OrganizationDescription.supportedServices] = details
            else:
                raise Exception("updateType not defined")
        
        affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], updatedWhen=updated)
        
        for key in sendSignals:
            match key:
                case OrganizationUpdateType.supportedServices:
                    signals.signalDispatcher.orgaServiceDeletion.send(None, orgaID=existingObj.hashedID, details=sendSignals[key])
        return None
    except (Exception) as error:
        logger.error(f"Error deleting orga details: {str(error)}")
        return error

##############################################
def logicsForOrganizationsAssignRole(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
    emailAddressOfUserToBeAdded = validatedInput["email"]
    roleID = validatedInput["roleID"]

    # fetch user id via E-Mail of the user
    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{emailAddressOfUserToBeAdded}"&search_engine=v3', headers=headers) )
    if isinstance(response, Exception):
        raise response
    userID = response[0]["user_id"]

    data = { "roles": [roleID]}
    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response

    retVal = sendEventViaWebsocket(orgID, baseURL, headers, "assignRole", userID)
    if isinstance(retVal, Exception):
        raise retVal
    
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DEFINED},assigned,{Logging.Object.OBJECT},role {roleID} to {emailAddressOfUserToBeAdded} in {orgID}," + str(datetime.datetime.now()))

#######################################################
def getOrganizationName(session, orgID, baseURL, baseHeader):
    """
    Get Name of the Organization

    :param orgID: the id of the current organization
    :type orgID: str
    :param baseURL: start of the url
    :type baseURL: str
    :param baseHeader: Header with basic stuff
    :type baseHeader: Dict
    :return: If successful, name of organization, error if not
    :rtype: str or error
    """
    try:
        if SessionContent.ORGANIZATION_NAME in session:
            if session[SessionContent.ORGANIZATION_NAME] != "":
                return session[SessionContent.ORGANIZATION_NAME]
        
        orgHashID = pgProfiles.ProfileManagementBase.getOrganizationHashID(orgaSubID=orgID)
        if orgHashID != "":
            return pgProfiles.ProfileManagementOrganization.getOrganizationName(orgHashID)
        
        res = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=baseHeader))
        if isinstance(res, Exception):
            raise res
        return res["display_name"].capitalize()
    except Exception as e:
        return e

##############################################
def logicsForOrganizationsFetchUsers(request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)

    orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
    if isinstance(orgaName, Exception):
        raise orgaName

    response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=headers) )
    if isinstance(response, Exception):
        raise response
    
    responseDict = response
    for idx, entry in enumerate(responseDict):
        resp = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{entry["user_id"]}/roles', headers=headers) )
        if isinstance(resp, Exception):
            raise resp
        responseDict[idx]["roles"] = resp
        for elemIdx in range(len(responseDict[idx]["roles"])):
            responseDict[idx]["roles"][elemIdx]["name"] = responseDict[idx]["roles"][elemIdx]["name"].replace(orgaName+"-", "")
        entry.pop("user_id")
    return responseDict

##############################################
def logicsForOrganizationsFetchInvitees(request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)

    orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
    if isinstance(orgaName, Exception):
        raise orgaName

    response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers) )
    if isinstance(response, Exception):
        raise response
    return response

##############################################
def logicsForOrganizationsCreateRole(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

    orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
    if isinstance(orgaName, Exception):
        raise orgaName
    
    # append organization name to the role name to avoid that two different organizations create the same role
    roleName = orgaName + "-" + validatedInput["roleName"]
    roleDescription = validatedInput["roleDescription"]

    data = { "name": roleName, "description": roleDescription}
    response = handleTooManyRequestsError( lambda: requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    
##############################################
def logicsForOrganizationsEditRole(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

    orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
    if isinstance(orgaName, Exception):
        raise orgaName

    roleID = validatedInput["roleID"]
    roleName = orgaName + "-" + validatedInput["roleName"]
    roleDescription = validatedInput["roleDescription"]

    data = { "name": roleName, "description": roleDescription}
    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    
    retVal = sendEventViaWebsocket(orgID, baseURL, headers, "editRole", roleID)
    if isinstance(retVal, Exception):
        raise retVal
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.EDITED},edited,{Logging.Object.OBJECT},role {roleName} for {orgID}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationSetPermissionsForRole(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
    roleID = validatedInput["roleID"]
    permissionList = validatedInput["permissionIDs"]

    data = {"permissions" : []}
    for entry in permissionList:
        data["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry})
    
    # get all permissions, remove them, then add anew. It's cumbersome but the API is the way it is
    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers) )
    if isinstance(response, Exception):
        raise response
    permissionsToBeRemoved = {"permissions": []}
    for entry in response:
        permissionsToBeRemoved["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry["permission_name"]})
    if len(permissionsToBeRemoved["permissions"]) > 0: # there are permissions that need removal
        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=permissionsToBeRemoved) )
        if isinstance(response, Exception):
            raise response
    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    
    retVal = sendEventViaWebsocket(orgID, baseURL, headers, "addPermissionsToRole", roleID)
    if isinstance(retVal, Exception):
        raise retVal
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DEFINED},set,{Logging.Object.OBJECT},permissions of role {roleID} in {orgID}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationsDeleteUser(request, userEMail):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

    # fetch user id via E-Mail of the user
    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{userEMail}"&search_engine=v3', headers=headers) )
    if isinstance(response, Exception):
        raise response
    userID = response[0]["user_id"]

    # delete person from organization via userID
    data = { "members": [userID]}
    response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    pgProfiles.ProfileManagementUser.deleteUser("", uID=userID)
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},user with email {userEMail} from {orgID}," + str(datetime.datetime.now()))
    
    # Send event to websocket
    retVal = sendEventViaWebsocket(orgID, baseURL, headers, "deleteUserFromOrganization", userID)
    if isinstance(retVal, Exception):
        raise retVal
    
##############################################
# def logicsForDeleteOrganization(request, orgaName, orgaID):
#     if SessionContent.MOCKED_LOGIN not in request.session or (SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is False):
#         baseURL = f"https://{settings.AUTH0_DOMAIN}"
#         headers = {
#             'authorization': f'Bearer {auth0.apiToken.accessToken}'
#         }
#         response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers) )
#         if isinstance(response, Exception):
#             loggerError.error(f"Error deleting organization: {str(response)}")
#             return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#     signals.signalDispatcher.orgaDeleted.send(None,orgaID=orgaID)
#     logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},organization {orgaName}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationsRemoveRole(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
    emailAddressOfUserToBeAdded = validatedInput["email"]
    roleID = validatedInput["roleID"]

    # fetch user id via E-Mail of the user
    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{emailAddressOfUserToBeAdded}"&search_engine=v3', headers=headers) )
    if isinstance(response, Exception):
        raise response
    userID = response[0]["user_id"]

    data = { "roles": [roleID]}
    response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers, json=data))
    if isinstance(response, Exception):
        raise response
    
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},removed,{Logging.Object.OBJECT},role {roleID} from {emailAddressOfUserToBeAdded} in {orgID}," + str(datetime.datetime.now()))
    # retVal = sendEventViaWebsocket(orgID, baseURL, headers, "removeRole", result)
    # if isinstance(retVal, Exception):
    #   raise retVal

##############################################
def logicsForOrganizationsGetRoles(request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)

    orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
    if isinstance(orgaName, Exception):
        raise orgaName

    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers) )
    if isinstance(response, Exception):
        raise response
    roles = response
    rolesOut = []
    for entry in roles:
        if orgaName in entry["name"]:
            entry["name"] = entry["name"].replace(orgaName+"-", "")
            rolesOut.append(entry)
    return rolesOut


##############################################
def logicsForOrganizationsDeleteRole(request,roleID):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

    response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}', headers=headers) )
    if isinstance(response, Exception):
        raise response
    
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.OBJECT},role {roleID} from {orgID}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationsGetPermissions():
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"

    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["resource-servers"]}/'+settings.AUTH0_PERMISSIONS_API_NAME, headers=headers) )
    if isinstance(response, Exception):
        raise response
    return response
        
##############################################
def logicsForOrganizationsGetPermissionsForRole(roleID):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"

    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers) )
    if isinstance(response, Exception):
        raise response
    return response

##############################################
def logicsForOrganizationsCreateNewOrganization(validatedInput):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"

    # create organization
    metadata = {} if "metadata" not in validatedInput else validatedInput["metadata"]
    displayName = validatedInput["display_name"]
    name =  displayName.strip().lower().replace(" ", "_")[:49]
    data = { "name": name, 
            "display_name": displayName, 
            "metadata": metadata,
            "enabled_connections": [ { "connection_id": auth0.auth0Config["IDs"]["connection_id"], "assign_membership_on_login": False } ] }

    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    
    org_id = response["id"]
    
    # create admin role
    roleName = displayName + "-" + "admin"
    roleDescription = "admin"

    data = { "name": roleName, "description": roleDescription}
    response = handleTooManyRequestsError( lambda: requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response
    roleID = response["id"]

    # connect admin role with permissions
    response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["resource-servers"]}/'+settings.AUTH0_PERMISSIONS_API_NAME, headers=headers) )
    if isinstance(response, Exception):
        raise response

    data = {"permissions": []}
    for entry in response["scopes"]:
        data["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry["value"]})

    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=data) )
    if isinstance(response, Exception):
        raise response

    # invite person to organization as admin
    email = validatedInput["email"]

    data = { "inviter": { "name": "Semper-KI" }, "invitee": { "email": email }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "roles": [ roleID ], "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "send_invitation_email": True }
    
    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{org_id}/invitations', headers=headers, json=data))
    if isinstance(response, Exception):
        raise response
    
    logger.info(f"{Logging.Subject.SYSTEM},Semper-KI,{Logging.Predicate.CREATED},created,{Logging.Object.ORGANISATION},{displayName} through user {email}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationDeleteInvite(request, invitationID):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

    # delete person from organization via invitationID
    response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations/{invitationID}', headers=headers) )
    if isinstance(response, Exception):
        raise response
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},user invitation from {orgID}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationsAddUser(validatedInput, request):    
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
    emailAddressOfUserToBeAdded = validatedInput["email"]
    roleID = validatedInput["roleID"]

    data = { "inviter": { "name": userName }, "invitee": { "email": emailAddressOfUserToBeAdded }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "roles":[roleID], "send_invitation_email": True }
    
    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers, json=data))
    if isinstance(response, Exception):
        raise response
    
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},invite,{Logging.Object.USER},user {emailAddressOfUserToBeAdded} to {orgID}," + str(datetime.datetime.now()))

##############################################
def logicsForOrganizationsGetInviteLink(validatedInput, request):
    headers = {
        'authorization': f'Bearer {auth0.apiToken.accessToken}',
        'content-Type': 'application/json',
        "Cache-Control": "no-cache"
    }
    baseURL = f"https://{settings.AUTH0_DOMAIN}"
    orgID = pgProfiles.ProfileManagementBase.getOrganizationID(request.session)
    userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
    emailAddressOfUserToBeAdded = validatedInput["email"]
    roleID = validatedInput["roleID"]

    data = { "inviter": { "name": userName }, "invitee": { "email": emailAddressOfUserToBeAdded }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "roles": [roleID], "send_invitation_email": False }
    
    response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers, json=data))
    if isinstance(response, Exception):
        raise response
    
    logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},invite,{Logging.Object.USER},user {emailAddressOfUserToBeAdded} to {orgID}," + str(datetime.datetime.now()))
    return response

##############################################
def logicsForGetOrganizationDeteails(request):
    returnVal = pgProfiles.ProfileManagementOrganization.getOrganization(request.session)
    if isinstance(returnVal, Exception):
        raise returnVal
    # parse addresses 
    if checkIfNestedKeyExists(returnVal, OrganizationDescription.details, OrganizationDetails.addresses):
        returnVal[OrganizationDescription.details][OrganizationDetails.addresses] = list(returnVal[OrganizationDescription.details][OrganizationDetails.addresses].values())
    return returnVal

##############################################

