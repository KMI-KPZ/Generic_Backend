"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of admin requests for organizations, api calls to auth0
"""

import datetime
import json, requests, logging
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema

from Generic_Backend.code_General.modelFiles.organizationModel import OrganizationDescription
from Generic_Backend.code_General.utilities import signals

from ..connections.postgresql import pgProfiles
from ..connections import auth0
from ..utilities.basics import checkIfNestedKeyExists, checkIfUserIsLoggedIn, handleTooManyRequestsError, checkIfRightsAreSufficient, ExceptionSerializerGeneric
from ..utilities import signals
from ..definitions import SessionContent, Logging, OrganizationDetails, EventsDescriptionGeneric

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
#######################################################
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
                event = {EventsDescriptionGeneric.eventType: EventsDescriptionGeneric.orgaEvent, EventsDescriptionGeneric.triggerEvent: True, EventsDescriptionGeneric.events: [{EventsDescriptionGeneric.reason: "roleChanged"}]}
                async_to_sync(channel_layer.group_send)(groupName, {
                    "type": "sendMessageJSON",
                    "dict": event,
                })
                signals.signalDispatcher.websocketEvent.send(None, event=event, userHashedID=userHashedID)

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
                            event = {EventsDescriptionGeneric.eventType: EventsDescriptionGeneric.orgaEvent, EventsDescriptionGeneric.triggerEvent: True, EventsDescriptionGeneric.events: [{EventsDescriptionGeneric.reason: "roleChanged"}]}
                            async_to_sync(channel_layer.group_send)(groupName, {
                                "type": "sendMessageJSON",
                                "dict": event,
                            })
                            signals.signalDispatcher.websocketEvent.send(None, event=event, userHashedID=userHashedID)
        elif eventName == "deleteUserFromOrganization":
            userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(userSubID=args)
            if userHashedID != "":
                groupName = userHashedID[:80]
                event = {EventsDescriptionGeneric.eventType: EventsDescriptionGeneric.orgaEvent, EventsDescriptionGeneric.triggerEvent: True, EventsDescriptionGeneric.events: [{EventsDescriptionGeneric.reason: "userDeleted"}]}
                async_to_sync(channel_layer.group_send)(groupName, {
                    "type": "sendMessageJSON",
                    "dict": event,
                })
                signals.signalDispatcher.websocketEvent.send(None, event=event, userHashedID=userHashedID)

        return True
    except Exception as e:
        return e


#########################################################################
# addOrganizationTest
#########################################################################
#TODO Add serializer for addOrganizationTest
#########################################################################
# Handler  
@extend_schema(
    summary="For testing",
    description=" ",
    request=None,
    tags=['Test'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn(json=True)
@api_view(["POST"])
def addOrganizationTest(request:Request):
    """
    For testing.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        returnVal = pgProfiles.ProfileManagementOrganization.addOrGetOrganization(request.session)
        if returnVal is not None:
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except (Exception) as exc:
        loggerError.error(f"Error creating organization: {str(exc)}")
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#######################################################
#########################################################################
# getOrganizationDetails
#######################################################
class SReqBrandingColor(serializers.Serializer):
    primary = serializers.CharField(max_length=200, default="HEX Color", allow_blank=True)
    page_background = serializers.CharField(max_length=200, default="HEX Color", allow_blank=True)
#######################################################
class SReqBrandingOrga(serializers.Serializer):
    logo_url = serializers.URLField(allow_blank=True)
    colors = SReqBrandingColor()
#######################################################
class SReqAddressOrga(serializers.Serializer):
    id = serializers.CharField(max_length=200, required=False, allow_blank=True)
    standard = serializers.BooleanField()
    country = serializers.CharField(max_length=200)
    city = serializers.CharField(max_length=200)
    zipcode = serializers.CharField(max_length=200)
    houseNumber = serializers.IntegerField()
    street = serializers.CharField(max_length=200)
    company = serializers.CharField(max_length=200, required=False, default="", allow_blank=True)
    lastName = serializers.CharField(max_length=200)
    firstName = serializers.CharField(max_length=200)
#######################################################
class SReqNotificationsContentOrga(serializers.Serializer):
    event = serializers.BooleanField(required=False)
    email = serializers.BooleanField(required=False)
#######################################################
class SReqProfileClassForNotifications(serializers.Serializer):
    organization = serializers.DictField(child=SReqNotificationsContentOrga(), required=False)
#######################################################
class SReqPriorities(serializers.Serializer):
    value = serializers.IntegerField(default=3)
#######################################################
class SResOrgaDetails(serializers.Serializer):
    addresses = SReqAddressOrga(many=True, required=False)
    email = serializers.EmailField(required=False, allow_blank=True)
    locale = serializers.CharField(max_length=200, required=False, allow_blank=True)
    notificationSettings = SReqProfileClassForNotifications(required=False)
    branding = SReqBrandingOrga(required=False)
    priorities = serializers.DictField(child=SReqPriorities(), required=False)
    taxID = serializers.CharField(max_length=200, required=False, allow_blank=True)
#######################################################
class SResOrga(serializers.Serializer):
    hashedID = serializers.CharField(max_length=200)
    name = serializers.CharField(max_length=200)
    details = SResOrgaDetails()
    accessedWhen = serializers.CharField(max_length=200)
    createdWhen = serializers.CharField(max_length=200)
    updatedWhen = serializers.CharField(max_length=200)
    supportedServices = serializers.ListField(child=serializers.IntegerField())
#########################################################################
# Handler  
@extend_schema(
    summary="Returns details about organization.",
    description=" ",
    request=None,
    tags=['FE - Profiles'],
    responses={
        200: SResOrga,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn(json=True)
@api_view(["GET"])
def getOrganizationDetails(request:Request):
    """
    Return details about organization. 

    :param request: GET request
    :type request: HTTP GET
    :return: Organization details
    :rtype: Json

    """
    # Read organization details from Database
    try:
        returnVal = pgProfiles.ProfileManagementOrganization.getOrganization(request.session)
        # parse addresses 
        if checkIfNestedKeyExists(returnVal, OrganizationDescription.details, OrganizationDetails.addresses):
            returnVal[OrganizationDescription.details][OrganizationDetails.addresses] = list(returnVal[OrganizationDescription.details][OrganizationDetails.addresses].values())

        outSerializer = SResOrga(data=returnVal)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except (Exception) as error:
        message = f"Error in {getOrganizationDetails.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# updateDetailsOfOrganization
#########################################################################
# Serializers
#######################################################
class SReqChangesOrga(serializers.Serializer):
    displayName = serializers.CharField(max_length=200, required=False)
    email = serializers.EmailField(required=False)
    address = SReqAddressOrga(required=False)
    locale = serializers.CharField(max_length=200, required=False, default="de-DE")
    notifications = SReqProfileClassForNotifications(required=False)
    supportedServices = serializers.ListField(child=serializers.IntegerField(), required=False)
    branding = SReqBrandingOrga(required=False)
    taxID = serializers.CharField(max_length=200, required=False)
    priorities = serializers.DictField(child=SReqPriorities(), required=False)

#######################################################
class SReqDeletionsOrga(serializers.Serializer):
    address = serializers.CharField(max_length=200, required=False, default="id")
    services = serializers.ListField(child=serializers.IntegerField(), required=False)
#######################################################
class SReqUpdateOrga(serializers.Serializer):
    changes = SReqChangesOrga(required=False)
    deletions = SReqDeletionsOrga(required=False)
#########################################################################
# Handler  
@extend_schema(
    summary="Update details of organization of that user.",
    description=" ",
    request=SReqUpdateOrga,
    tags=['FE - Profiles'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["PATCH"])
def updateDetailsOfOrganization(request:Request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        inSerializer = SReqUpdateOrga(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {updateDetailsOfOrganization.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        content = inSerializer.data
        if "changes" in content:
            flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content["changes"])
            if isinstance(flag, Exception):
                raise flag
        if "deletions" in content:
            flag = pgProfiles.ProfileManagementOrganization.deleteContent(request.session, content["deletions"])
            if isinstance(flag, Exception):
                raise flag
        
        logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},details of {pgProfiles.ProfileManagementOrganization.getOrganization(request.session)[OrganizationDescription.name]}," + str(datetime.datetime.now()))
        return Response("Success", status=status.HTTP_200_OK)
    except (Exception) as error:
        message = f"Error in {updateDetailsOfOrganization.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# deleteOrganization
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes an organization from the database and auth0.",
    description=" ",
    request=None,
    tags=['FE - Profiles'],
    responses={
        200: None,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["DELETE"])
def deleteOrganization(request:Request):
    """
    Deletes an organization from the database and auth0.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        orgaID = pgProfiles.ProfileManagementOrganization.getOrganizationID(request.session)
        orgaName = pgProfiles.ProfileManagementOrganization.getOrganizationName(pgProfiles.ProfileManagementOrganization.getOrganizationHashID(request.session))
        flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
        if flag is True:
            if SessionContent.MOCKED_LOGIN not in request.session or (SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is False):
                baseURL = f"https://{settings.AUTH0_DOMAIN}"
                headers = {
                    'authorization': f'Bearer {auth0.apiToken.accessToken}'
                }
                response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers) )
                if isinstance(response, Exception):
                    loggerError.error(f"Error deleting organization: {str(response)}")
                    return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            signals.signalDispatcher.orgaDeleted.send(None,orgaID=orgaID)
            logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},organization {orgaName}," + str(datetime.datetime.now()))
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as error:
        message = f"Error in {deleteOrganization.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

#########################################################################
# organizations_getInviteLink
#########################################################################
# serializer for organizations_getInviteLink
#######################################################
class SReqRoleAndMail(serializers.Serializer):
    email = serializers.EmailField()
    roleID = serializers.CharField(max_length=200)
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to invite someone via e-mail and retrieve the link",
    description=" ",
    request=SReqRoleAndMail,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["POST"])
def organizations_getInviteLink(request:Request):
    """
    Ask Auth0 API to invite someone via e-mail and retrieve the link

    :param request: Request with content as json
    :type request: HTTP POST
    :return: If successful or not
    :rtype: HTTPResponse
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")
        
        inSerializer = SReqRoleAndMail(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_getInviteLink.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        return Response(response["invitation_url"], status=status.HTTP_200_OK)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while obtaining invite link: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_addUser
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to invite someone via e-mail",
    description=" ",
    request=SReqRoleAndMail,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["POST"])
def organizations_addUser(request:Request):
    """
    Ask Auth0 API to invite someone via e-mail

    :param request: Request with content as json
    :type request: HTTP POST
    :return: If successful or not
    :rtype: HTTPResponse
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqRoleAndMail(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_addUser.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while adding user: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_fetchUsers
#########################################################################
# serializer for organizations_fetchUsers
#######################################################
class SResRolesForUsers(serializers.Serializer):
    id = serializers.CharField(max_length=200)
    name = serializers.CharField(max_length=200)
#######################################################
class SResUsersAndRoles(serializers.Serializer):
    picture = serializers.URLField(required=False, allow_blank=True)
    name = serializers.CharField(max_length=200)
    email = serializers.EmailField()
    roles = SResRolesForUsers(many=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API for all users of an organization",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: serializers.ListSerializer(child=SResUsersAndRoles()),
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["GET"])
def organizations_fetchUsers(request:Request):
    """
    Ask Auth0 API for all users of an organization

    :param request: Request with session in it
    :type request: HTTP GET
    :return: If successful or not
    :rtype: Json or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

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

        outSerializer = SResUsersAndRoles(data=responseDict, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except Exception as e:
        loggerError.error(f'Generic Exception while fetching users: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#########################################################################
# organizations_fetchInvitees
#########################################################################
# serializer for organizations_fetchInvitees
#######################################################
class SResInvitee(serializers.Serializer):
    email = serializers.EmailField()
#######################################################
class SResInviter(serializers.Serializer):
    name = serializers.CharField(max_length=200)
#######################################################
class SResInvites(serializers.Serializer):
    id = serializers.CharField()
    inviter = SResInviter()
    invitee = SResInvitee()
    invitation_url = serializers.URLField()
    created_at = serializers.CharField()
    expires_at = serializers.CharField()
    roles = serializers.ListField(child=serializers.CharField())
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API for all invited people of an organization",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: serializers.ListSerializer(child=SResInvites()),
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["GET"])
def organizations_fetchInvitees(request:Request):
    """
    Ask Auth0 API for all invited people of an organization

    :param request: Request with session in it
    :type request: HTTP GET
    :return: If successful or not
    :rtype: Json or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

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

        outSerializer = SResInvites(data=response, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except Exception as e:
        loggerError.error(f'Generic Exception while fetching users: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizations_deleteUser
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to revoke and invitation",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: None,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["DELETE"])
def organizations_deleteInvite(request:Request, invitationID:str):
    """
    Ask Auth0 API to revoke and invitation

    :param request: Request with parameter
    :type request: HTTP DELETE
    :return: If successful or not
    :rtype: HTTPResponse or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

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
        
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while deleting user: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_deleteUser
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to delete someone from an organization via their mail address",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: None,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["DELETE"])
def organizations_deleteUser(request:Request, userEMail:str):
    """
    Ask Auth0 API to delete someone from an organization via their mail address

    :param request: Request with parameter
    :type request: HTTP DELETE
    :return: If successful or not
    :rtype: HTTPResponse or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

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
        
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while deleting user: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# organizations_createRole
#########################################################################
# serializer for organizations_createRole
#######################################################
class SReqCreateRole(serializers.Serializer):
    roleName = serializers.CharField(max_length=200)
    roleDescription = serializers.CharField(max_length=200, allow_blank=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to create a new role",
    description=" ",
    request=SReqCreateRole,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=True)
@api_view(["POST"])
def organizations_createRole(request:Request):
    """
    Ask Auth0 API to create a new role

    :param request: request with json as content
    :type request: HTTP POST
    :return: If successful or not
    :rtype: JSON or Error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

        inSerializer = SReqCreateRole(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_createRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},created,{Logging.Object.OBJECT},role {roleName} in {orgID}," + str(datetime.datetime.now()))
        return Response("Success", status=status.HTTP_200_OK)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while creating role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_assignRole
#########################################################################
# Handler  
@extend_schema(
    summary="Assign a role to a person",
    description=" ",
    request=SReqRoleAndMail,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["PATCH"])
def organizations_assignRole(request:Request):
    """
    Assign a role to a person

    :param request: request with content as json
    :type request: HTTP PATCH
    :return: If successful or not
    :rtype: HTTPResponse
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqRoleAndMail(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_assignRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while assigning role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# organizations_removeRole
#########################################################################
# Handler  
@extend_schema(
    summary="Remove a role from a person",
    description=" ",
    request=SReqRoleAndMail,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["PATCH"])
def organizations_removeRole(request:Request):
    """
    Remove a role from a person

    :param request: request with content as json
    :type request: HTTP PATCH
    :return: If successful or not
    :rtype: True or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqRoleAndMail(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_removeRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        #     raise retVal
        return Response("Success", status=status.HTTP_200_OK)
        
    except Exception as e:
        loggerError.error(f'Generic Exception while removing role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_editRole
#########################################################################
# serializer for organizations_editRole
#######################################################
class SReqEditRole(serializers.Serializer):
    roleID = serializers.CharField(max_length=200)
    roleName = serializers.CharField(max_length=200)
    roleDescription = serializers.CharField(max_length=200, allow_blank=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Ask Auth0 API to edit a role",
    description=" ",
    request=SReqEditRole,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    }
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["PATCH"])
def organizations_editRole(request:Request):
    """
    Ask Auth0 API to edit a role

    :param request: request with content as json
    :type request: HTTP POST
    :return: If successful true or an error if not
    :rtype: Bool or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqEditRole(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_editRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while editing role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_getRoles
#########################################################################
# serializer for organizations_getRoles
#######################################################
class SResRoles(serializers.Serializer):
    id = serializers.CharField(max_length=200)
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=200, allow_blank=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Fetch all roles for the organization",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: serializers.ListSerializer(child=SResRoles()),
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=True)
@api_view(["GET"])
def organizations_getRoles(request:Request):
    """
    Fetch all roles for the organization

    :param request: request with session
    :type request: HTTP GET
    :return: If successful, list of roles for that organization, error if not
    :rtype: JSON or error
    """
    try:

        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

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

        outSerializer = SResRoles(data=rolesOut, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while fetching roles: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_deleteRole
#########################################################################
# Handler  
@extend_schema(
    summary="Delete role via ID",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: None,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["DELETE"])
def organizations_deleteRole(request:Request, roleID:str):
    """
    Delete role via ID

    :param request: request with content as json
    :type request: HTTP DELETE
    :return: If successful or not
    :rtype: HTTPResponse or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

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
        return Response("Success", status=status.HTTP_200_OK)
        
    except Exception as e:
        loggerError.error(f'Generic Exception while deleting role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_setPermissionsForRole
#########################################################################
# serializer for organizations_setPermissionsForRole
#######################################################
class SReqPermissionsAndRoles(serializers.Serializer):
    roleID = serializers.CharField(max_length=200)
    permissionIDs = serializers.ListField(child=serializers.CharField())
#########################################################################
# Handler 
@extend_schema(
    summary="Add Permissions to role",
    description=" ",
    request=SReqPermissionsAndRoles,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
) 
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=False)
@api_view(["PATCH"])
def organizations_setPermissionsForRole(request:Request):
    """
    Add Permissions to role

    :param request: request with content as json
    :type request: HTTP PATCH
    :return: If successful or not
    :rtype: HTTPResponse or error
    """    
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqPermissionsAndRoles(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_getPermissionsForRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as e:
        loggerError.error(f'Generic Exception while setting permissions for role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_getPermissions
#########################################################################
# serializer for organizations_getPermissions
#######################################################
class SResPermissions(serializers.Serializer):
    value = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Get all Permissions",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: serializers.ListSerializer(child=SResPermissions()),
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    }
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=True)
@api_view(["GET"])
def organizations_getPermissions(request:Request):
    """
    Get all Permissions

    :param request: request with session
    :type request: HTTP GET
    :return: If successful, list of permissions for role as array, error if not
    :rtype: JSON or error
    """ 
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"

        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["resource-servers"]}/'+settings.AUTH0_PERMISSIONS_API_NAME, headers=headers) )
        if isinstance(response, Exception):
            raise response
        
        outSerializer = SResPermissions(data=response["scopes"], many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching permissions: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_getPermissionsForRole
#########################################################################
# serializer for organizations_getPermissionsForRole
#######################################################
class SResPermissionsForRole(serializers.Serializer):
    resource_server_identifier = serializers.CharField(max_length=300)
    permission_name = serializers.CharField(max_length=200)
    resource_server_name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=200, allow_blank=True)
#########################################################################
# Handler  
@extend_schema(
    summary="Get Permissions of role",
    description=" ",
    request=None,
    tags=['FE - Organizations'],
    responses={
        200: serializers.ListSerializer(child=SResPermissionsForRole()),
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    }
)
@checkIfUserIsLoggedIn()
@checkIfRightsAreSufficient(json=True)
@api_view(["GET"])
def organizations_getPermissionsForRole(request:Request, roleID:str):
    """
    Get Permissions of role

    :param request: request with content as json
    :type request: HTTP GET
    :return: If successful, list of permissions for role as array, error if not
    :rtype: JSON or error
    """    
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return JsonResponse({})

        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            "Cache-Control": "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"

        response = handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{roleID}/permissions', headers=headers) )
        if isinstance(response, Exception):
            raise response
        
        outSerializer = SResPermissionsForRole(data=response, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)

    except Exception as e:
        loggerError.error(f'Generic Exception while fetching permissions for role: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizations_createNewOrganization
#########################################################################
# serializer for organizations_createNewOrganization
#######################################################
class SReqNewOrganization(serializers.Serializer):
    metadata = serializers.DictField(required=False, allow_empty=True)
    display_name = serializers.CharField(max_length=200, min_length=3)
    email = serializers.EmailField()
#########################################################################
# Handler  
@extend_schema(
    summary="Create a new organization",
    description="Create a new organization, create an admin role, invite a person via email as admin. All via Auth0s API.",
    request=SReqNewOrganization,
    tags=['FE - Organizations'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        429: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    }
)
@api_view(["POST"])
def organizations_createNewOrganization(request:Request):
    """
    Create a new organization, create an admin role, invite a person via email as admin.
    All via Auth0s API.

    :param request: request with content as json
    :type request: HTTP POST
    :return: Successfull or not
    :rtype: HTTPResponse
    """    

    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")

        inSerializer = SReqNewOrganization(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {organizations_createNewOrganization.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

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
        
        return Response("Success", status=status.HTTP_200_OK)
    
    except Exception as e:
        loggerError.error(f'Generic Exception while creating organization: {e}')
        if "many requests" in e.args[0]:
            return Response("Failed - " + str(e), status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response("Failed - " + str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)    

