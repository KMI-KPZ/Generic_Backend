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

from ..utilities import signals
from ..modelFiles.organizationModel import OrganizationDescription
from ..connections.postgresql import pgProfiles, pgEvents
from ..connections import auth0
from ..utilities.basics import checkIfNestedKeyExists, checkIfUserIsLoggedIn, handleTooManyRequestsError, checkIfRightsAreSufficient, ExceptionSerializerGeneric
from ..definitions import SessionContent, Logging, OrganizationDetails, EventsDescriptionGeneric
from ..logics.organizationLogics import *

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
#######################################################


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
    coordinates = serializers.ListField(child=serializers.FloatField(), required=False)
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
    services = serializers.DictField(required=False, allow_empty=True)
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
        returnVal, value = logicsForGetOrganizationDetails(request)

        if isinstance(returnVal, Exception):
            message = str(returnVal)
            loggerError.error(returnVal)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": returnVal})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
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
    locale = serializers.CharField(max_length=200, required=False)#, default="de-DE")
    notifications = SReqProfileClassForNotifications(required=False)
    supportedServices = serializers.ListField(child=serializers.IntegerField(), required=False)
    branding = SReqBrandingOrga(required=False)
    taxID = serializers.CharField(max_length=200, required=False)
    priorities = serializers.DictField(child=SReqPriorities(), required=False)
    services = serializers.DictField(required=False, allow_empty=True)

#######################################################
class SReqDeletionsOrga(serializers.Serializer):
    address = serializers.CharField(max_length=200, required=False)
    supportedServices = serializers.ListField(child=serializers.IntegerField(), required=False)

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
        exception, value = logicsForDeleteOrganization(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {deleteOrganization.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizationsGetInviteLink
#########################################################################
# serializer for organizationsGetInviteLink
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
def organizationsGetInviteLink(request:Request):
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
            message = f"Verification failed in {organizationsGetInviteLink.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        response, exception, value = logicsForOrganizationsGetInviteLink(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response(response["invitation_url"], status=status.HTTP_200_OK)
    
    except Exception as error:
        message = f"Error in {organizationsGetInviteLink.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizationsAddUser
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
def organizationsAddUser(request:Request):
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
            message = f"Verification failed in {organizationsAddUser.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        exception, value = logicsForOrganizationsAddUser(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsAddUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizationsFetchUsers
#########################################################################
# serializer for organizationsFetchUsers
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
def organizationsFetchUsers(request:Request):
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
        responseDict, exception, value = logicsForOrganizationsFetchUsers(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        outSerializer = SResUsersAndRoles(data=responseDict, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except Exception as error:
        message = f"Error in {organizationsFetchUsers.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
#########################################################################
# organizationsFetchInvitees
#########################################################################
# serializer for organizationsFetchInvitees
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
def organizationsFetchInvitees(request:Request):
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

        response, exception, value = logicsForOrganizationsFetchInvitees(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        outSerializer = SResInvites(data=response, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except Exception as error:
        message = f"Error in {organizationsFetchInvitees.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



#########################################################################
# organizationsDeleteInvite
#########################################################################
# Handler
@extend_schema(
    summary="Ask Auth0 API to revoke an invitation",
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
def organizationsDeleteInvite(request:Request, invitationID:str):
    """
    Ask Auth0 API to revoke an invitation

    :param request: Request with parameter
    :type request: HTTP DELETE
    :return: If successful or not
    :rtype: HTTPResponse or error
    """
    try:
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            return Response("Mock")
        
        exception, value = logicsForOrganizationDeleteInvite(request, invitationID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsDeleteInvite.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizationsDeleteUser
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
def organizationsDeleteUser(request:Request, userEMail:str):
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

        exception, value = logicsForOrganizationsDeleteUser(request, userEMail)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsDeleteUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
#########################################################################
# organizationsCreateRole
#########################################################################
# serializer for organizationsCreateRole
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
def organizationsCreateRole(request:Request):
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
            message = f"Verification failed in {organizationsCreateRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        
        exception, value = logicsForOrganizationsCreateRole(validatedInput, request)

        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
    
    except Exception as error:
        message = f"Error in {organizationsCreateRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#########################################################################
# organizationsAssignRole
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
def organizationsAssignRole(request:Request):
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
            message = f"Verification failed in {organizationsAssignRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        exception, value = logicsForOrganizationsAssignRole(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsAssignRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# organizationsRemoveRole
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
def organizationsRemoveRole(request:Request):
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
            message = f"Verification failed in {organizationsRemoveRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        exception, value = logicsForOrganizationsRemoveRole(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
        
    except Exception as error:
        message = f"Error in {organizationsRemoveRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsEditRole
#########################################################################
# serializer for organizationsEditRole
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
def organizationsEditRole(request:Request):
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
            message = f"Verification failed in {organizationsEditRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

        exception, value = logicsForOrganizationsEditRole(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsEditRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsGetRoles
#########################################################################
# serializer for organizationsGetRoles
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
def organizationsGetRoles(request:Request):
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
        
        rolesOut, exception, value = logicsForOrganizationsGetRoles(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
              
        outSerializer = SResRoles(data=rolesOut, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    
    except Exception as error:
        message = f"Error in {organizationsGetRoles.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsDeleteRole
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
def organizationsDeleteRole(request:Request, roleID:str):
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

        exception, value = logicsForOrganizationsDeleteRole(request, roleID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsDeleteRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsSetPermissionsForRole
#########################################################################
# serializer for organizationsSetPermissionsForRole
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
def organizationsSetPermissionsForRole(request:Request):
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
            message = f"Verification failed in {organizationsSetPermissionsForRole.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        exception, value = logicsForOrganizationSetPermissionsForRole(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response("Success", status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {organizationsSetPermissionsForRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsGetPermissions
#########################################################################
# serializer for organizationsGetPermissions
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
def organizationsGetPermissions(request:Request):
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
        
        response, exception, value = logicsForOrganizationsGetPermissions()
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        outSerializer = SResPermissions(data=response["scopes"], many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)

    except Exception as error:
        message = f"Error in {organizationsGetPermissions.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsGetPermissionsForRole
#########################################################################
# serializer for organizationsGetPermissionsForRole
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
def organizationsGetPermissionsForRole(request:Request, roleID:str):
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
        
        response, exception, value = logicsForOrganizationsGetPermissionsForRole(roleID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        outSerializer = SResPermissionsForRole(data=response, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)

    except Exception as error:
        message = f"Error in {organizationsGetPermissionsForRole.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# organizationsCreateNewOrganization
#########################################################################
# serializer for organizationsCreateNewOrganization
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
def organizationsCreateNewOrganization(request:Request):
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
            message = f"Verification failed in {organizationsCreateNewOrganization.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data

        exception, value = logicsForOrganizationsCreateNewOrganization(validatedInput)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response("Success", status=status.HTTP_200_OK)
    
    except Exception as error:
        message = f"Error in {organizationsCreateNewOrganization.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
