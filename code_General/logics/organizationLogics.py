"""
Generic Backend

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

from logging import getLogger

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

@staticmethod
def getOrganizationID(session):
    """
    Retrieve Organization ID

    :param session: session
    :type session: Str
    :return: ID of the organization
    :rtype: Str

    """
    orgaID = session["user"]["userinfo"]["org_id"]
    return orgaID

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
            response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=baseHeader, timeout=5))
            if isinstance(response, Exception):
                raise response
            responseDict = response
            for user in responseDict:
                userID = user["user_id"]
                
                resp = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=baseHeader, timeout=5) )
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
def logicsForOrganizationsAssignRole(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        emailAddressOfUserToBeAdded = validatedInput["email"]
        roleID = validatedInput["roleID"]

        # fetch user id via E-Mail of the user
        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{emailAddressOfUserToBeAdded}"&search_engine=v3', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        userID = response[0]["user_id"]

        data = { "roles": [roleID]}
        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response

        retVal = sendEventViaWebsocket(orgID, baseURL, headers, "assignRole", userID)
        if isinstance(retVal, Exception):
            raise retVal
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DEFINED},assigned,{Logging.Object.OBJECT},role {roleID} to {emailAddressOfUserToBeAdded} in {orgID}," + str(datetime.datetime.now()))
        return (None, 200)

    except Exception as e:
        return (e, 500)

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
        
        res = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=baseHeader, timeout=5))
        if isinstance(res, Exception):
            raise res
        return res["display_name"].capitalize()
    except Exception as e:
        return e

##############################################
def logicsForOrganizationsFetchUsers(request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)

        orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
        if isinstance(orgaName, Exception):
            raise orgaName

        response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        responseDict = response
        for idx, entry in enumerate(responseDict):
            resp = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{entry["user_id"]}/roles', headers=headers, timeout=5) )
            if isinstance(resp, Exception):
                raise resp
            responseDict[idx]["roles"] = resp
            for elemIdx in range(len(responseDict[idx]["roles"])):
                responseDict[idx]["roles"][elemIdx]["name"] = responseDict[idx]["roles"][elemIdx]["name"].replace(orgaName+"-", "")
            entry.pop("user_id")
        return (responseDict, None, 200)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while fetching users of Organization: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsFetchInvitees(request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)

        orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
        if isinstance(orgaName, Exception):
            raise orgaName

        response = handleTooManyRequestsError(lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        return (response, None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching Invitees: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsCreateRole(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

        orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
        if isinstance(orgaName, Exception):
            raise orgaName
        
        # append organization name to the role name to avoid that two different organizations create the same role
        roleName = orgaName + "-" + validatedInput["roleName"]
        roleDescription = validatedInput["roleDescription"]

        data = { "name": roleName, "description": roleDescription}
        response = handleTooManyRequestsError( lambda: requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},created,{Logging.Object.OBJECT},role {roleName} for {orgID}," + str(datetime.datetime.now()))

        return (None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while creating role: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)
    
##############################################
def logicsForOrganizationsEditRole(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

        orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
        if isinstance(orgaName, Exception):
            raise orgaName

        roleID = validatedInput["roleID"]
        roleName = orgaName + "-" + validatedInput["roleName"]
        roleDescription = validatedInput["roleDescription"]

        data = { "name": roleName, "description": roleDescription}
        response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        retVal = sendEventViaWebsocket(orgID, baseURL, headers, "editRole", roleID)
        if isinstance(retVal, Exception):
            raise retVal
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.EDITED},edited,{Logging.Object.OBJECT},role {roleName} for {orgID}," + str(datetime.datetime.now()))
        return (None, 200)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while editing role: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)
        
##############################################
def logicsForOrganizationSetPermissionsForRole(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        roleID = validatedInput["roleID"]
        permissionList = validatedInput["permissionIDs"]

        data = {"permissions" : []}
        for entry in permissionList:
            data["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry})
        
        # get all permissions, remove them, then add anew. It's cumbersome but the API is the way it is
        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        permissionsToBeRemoved = {"permissions": []}
        for entry in response:
            permissionsToBeRemoved["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry["permission_name"]})
        if len(permissionsToBeRemoved["permissions"]) > 0: # there are permissions that need removal
            response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=permissionsToBeRemoved, timeout=5) )
            if isinstance(response, Exception):
                raise response
        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        retVal = sendEventViaWebsocket(orgID, baseURL, headers, "addPermissionsToRole", roleID)
        if isinstance(retVal, Exception):
            raise retVal
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DEFINED},set,{Logging.Object.OBJECT},permissions of role {roleID} in {orgID}," + str(datetime.datetime.now()))
        return(None, 200)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while setting permissions of a role: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsDeleteUser(request, userEMail):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

        # fetch user id via E-Mail of the user
        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{userEMail}"&search_engine=v3', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        userID = response[0]["user_id"]

        # delete person from organization via userID
        data = { "members": [userID]}
        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        userHashID = pgProfiles.ProfileManagementUser.getUserHashID(userSubID=userID)
        
        # Send event to websocket
        retVal = sendEventViaWebsocket(orgID, baseURL, headers, "deleteUserFromOrganization", userID)
        if isinstance(retVal, Exception):
            raise retVal
        
        pgProfiles.ProfileManagementUser.deleteUser("", uHashedID=userHashID) # TODO this may have more consequences than necessary
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},user with email {userEMail} from {orgID}," + str(datetime.datetime.now()))
        return (None, 200)
        
    except Exception as e:
        loggerError.error(f'Generic Exception while Deleting User from organization: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)
    
##############################################
def logicsForDeleteOrganization(request):
    try:
        orgaID = getOrganizationID(request.session)
        orgaName = pgProfiles.ProfileManagementOrganization.getOrganizationName(pgProfiles.ProfileManagementOrganization.getOrganizationHashID(request.session))
        flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
        if flag is True:    
            if SessionContent.MOCKED_LOGIN not in request.session or (SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is False):
                baseURL = f"https://{settings.AUTH0_DOMAIN}"
                headers = {
                    'authorization': f'Bearer {auth0.apiToken.accessToken}'
                }
                response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers, timeout=5) )
                if isinstance(response, Exception):
                    loggerError.error(f"Error deleting organization: {str(response)}")
                    return (response, 500)
            
            signals.signalDispatcher.orgaDeleted.send(None,orgaID=orgaID)
            logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},organization {orgaName}," + str(datetime.datetime.now()))
            return (None, 200)
        else:
            return (Exception("Failed to delete Organization"), 500)
    except Exception as e:
        loggerError.error("Error in logicForDeleteOrganization: %s" % str(e))
        return (e, 500)

##############################################
def logicsForOrganizationsRemoveRole(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        emailAddressOfUserToBeAdded = validatedInput["email"]
        roleID = validatedInput["roleID"]

        # fetch user id via E-Mail of the user
        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}?q=email:"{emailAddressOfUserToBeAdded}"&search_engine=v3', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        userID = response[0]["user_id"]

        data = { "roles": [roleID]}
        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers, json=data, timeout=5))
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},removed,{Logging.Object.OBJECT},role {roleID} from {emailAddressOfUserToBeAdded} in {orgID}," + str(datetime.datetime.now()))
        # retVal = sendEventViaWebsocket(orgID, baseURL, headers, "removeRole", result)
        # if isinstance(retVal, Exception):
        #   raise retVal
        return (None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while removing role: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsGetRoles(request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)

        orgaName = getOrganizationName(request.session, orgID, baseURL, headers)
        if isinstance(orgaName, Exception):
            raise orgaName

        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        roles = response
        rolesOut = []
        for entry in roles:
            if orgaName in entry["name"]:
                entry["name"] = entry["name"].replace(orgaName+"-", "")
                rolesOut.append(entry)
        return (rolesOut, None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching roles: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)


##############################################
def logicsForOrganizationsDeleteRole(request,roleID):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.OBJECT},role {roleID} from {orgID}," + str(datetime.datetime.now()))
        return (None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching permissions for role: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsGetPermissions():
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"

        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["resource-servers"]}/'+settings.AUTH0_PERMISSIONS_API_NAME, headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        return (response, None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching permissions: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)
##############################################
def logicsForOrganizationsGetPermissionsForRole(roleID):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"

        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        return (response, None, 200) 

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching permissions for role: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)    

##############################################
def logicsForOrganizationsCreateNewOrganization(validatedInput):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"

        # create organization
        metadata = {} if "metadata" not in validatedInput else validatedInput["metadata"]
        displayName = validatedInput["display_name"]
        name =  displayName.strip().lower().replace(" ", "_")[:49] # auth0 has some very hard restrictions on the unique name of the organization
        name = ''.join(e for e in name if (e.isalnum() or e in "_-") and e not in "²³äüö").rstrip("-_")
        data = { "name": name,
                "display_name": displayName, 
                "metadata": metadata,
                "enabled_connections": [ { "connection_id": auth0.auth0Config["IDs"]["connection_id"], "assign_membership_on_login": False } ] }

        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        
        org_id = response["id"]
        
        # create admin role
        roleName = displayName + "-" + "admin"
        roleDescription = "admin"

        data = { "name": roleName, "description": roleDescription}
        response = handleTooManyRequestsError( lambda: requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response
        roleID = response["id"]

        # connect admin role with permissions
        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["resource-servers"]}/'+settings.AUTH0_PERMISSIONS_API_NAME, headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response

        data = {"permissions": []}
        for entry in response["scopes"]:
            data["permissions"].append({"resource_server_identifier": settings.AUTH0_PERMISSIONS_API_NAME, "permission_name": entry["value"]})

        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers, json=data, timeout=5) )
        if isinstance(response, Exception):
            raise response

        # invite person to organization as admin
        email = validatedInput["email"]

        # TODO change name of inviter!
        data = { "inviter": { "name": "Semper-KI" }, "invitee": { "email": email }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "roles": [ roleID ], "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "send_invitation_email": True }
        
        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{org_id}/invitations', headers=headers, json=data, timeout=5))
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.SYSTEM},SYSTEM,{Logging.Predicate.CREATED},created,{Logging.Object.ORGANISATION},{displayName} through user {email}," + str(datetime.datetime.now()))
        return (None, 200)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while Creating new Organization: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)
    
##############################################
def logicsForOrganizationDeleteInvite(request, invitationID):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)

        # delete person from organization via invitationID
        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations/{invitationID}', headers=headers, timeout=5) )
        if isinstance(response, Exception):
            raise response
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},user invitation from {orgID}," + str(datetime.datetime.now()))
        return (None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while deleting Invite: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsAddUser(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        emailAddressOfUserToBeAdded = validatedInput["email"]
        roleID = validatedInput["roleID"]

        data = { "inviter": { "name": userName }, "invitee": { "email": emailAddressOfUserToBeAdded }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "roles":[roleID], "send_invitation_email": True }
        
        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers, json=data, timeout=5))
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},invite,{Logging.Object.USER},user {emailAddressOfUserToBeAdded} to {orgID}," + str(datetime.datetime.now()))
        return (None, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while adding User to organization: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)

##############################################
def logicsForOrganizationsGetInviteLink(validatedInput, request):
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        orgID = getOrganizationID(request.session)
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        emailAddressOfUserToBeAdded = validatedInput["email"]
        roleID = validatedInput["roleID"]

        data = { "inviter": { "name": userName }, "invitee": { "email": emailAddressOfUserToBeAdded }, "client_id": settings.AUTH0_ORGA_CLIENT_ID, "connection_id": auth0.auth0Config["IDs"]["connection_id"], "ttl_sec": 0, "roles": [roleID], "send_invitation_email": False }
        
        response = handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/invitations', headers=headers, json=data, timeout=5))
        if isinstance(response, Exception):
            raise response
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},invite,{Logging.Object.USER},user {emailAddressOfUserToBeAdded} to {orgID}," + str(datetime.datetime.now()))
        return (response, None, 200)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while obtaining invite link: {e}')
        if "many requests" in e.args[0]:
            return (None, Exception("Failed - " + str(e)), 429)
        else:
            return (None, Exception("Failed - " + str(e)), 500)
            

##############################################
def logicsForGetOrganizationDetails(request):
    try:
        returnVal = pgProfiles.ProfileManagementOrganization.getOrganization(request.session)
        if isinstance(returnVal, Exception):
            raise returnVal
        # parse addresses 
        if checkIfNestedKeyExists(returnVal, OrganizationDescription.details, OrganizationDetails.addresses):
            returnVal[OrganizationDescription.details][OrganizationDetails.addresses] = list(returnVal[OrganizationDescription.details][OrganizationDetails.addresses].values())
        return (returnVal, 200)

    except Exception as e:
        loggerError.error(f'Generic Exception while obtaining OrganizationDetails: {e}')
        if "many requests" in e.args[0]:
            return (Exception("Failed - " + str(e)), 429)
        else:
            return (Exception("Failed - " + str(e)), 500)

##############################################

