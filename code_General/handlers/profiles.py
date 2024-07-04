"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of database requests
"""

import datetime, json, logging, requests

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from rest_framework.request import Request
from drf_spectacular.utils import extend_schema
from drf_spectacular.utils import OpenApiParameter

from ..utilities import basics
from ..connections.postgresql import pgProfiles
from ..connections import auth0
from ..utilities.basics import handleTooManyRequestsError, ExceptionSerializer
from ..definitions import SessionContent, ProfileClasses, UserDescription, OrganizationDescription, Logging

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
##############################################

#########################################################################
# addUserTest
#"addUser": ("private/profile_addUser/",profiles.addUserTest)
#########################################################################
#TODO Add serializer for addUserTest
#########################################################################
# Handler  
@extend_schema(
    summary="For testing",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@api_view(["POST"])
def addUserTest(request:Request):
    """
    For testing.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP response
    :rtype: HTTP status

    """
    try:

        if request.session[SessionContent.PG_PROFILE_CLASS] == ProfileClasses.organization:
            orgaObj = pgProfiles.ProfileManagementBase.getOrganizationObject(request.session)
            returnVal = pgProfiles.ProfileManagementOrganization.addUserIfNotExists(request.session, orgaObj)
            if isinstance(returnVal, Exception):
                raise returnVal
        else:
            returnVal = pgProfiles.ProfileManagementUser.addUserIfNotExists(request.session)
            if isinstance(returnVal, Exception):
                raise returnVal

        return Response("Success", status=status.HTTP_200_OK)
    except (Exception) as error:
        message = f"Error in addUserTest : {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializer(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
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
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
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

##############################################
# @checkIfUserIsLoggedIn()
# @require_http_methods(["GET"])
# def getUserTest(request):
#     """
#     Same as getUser but for testing.

#     :param request: GET request
#     :type request: HTTP GET
#     :return: User details from database
#     :rtype: JSON

#     """
#     return JsonResponse(pgProfiles.ProfileManagement.getUser(request.session))

#######################################################
#########################################################################
# getOrganizationDetails
#"getOrganization": ("public/getOrganization/",profiles.getOrganizationDetails)
#########################################################################
#TODO Add serializer for getOrganizationDetails
#########################################################################
# Handler  
@extend_schema(
    summary="Returns details about organization.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
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
        return Response(returnVal, status=status.HTTP_200_OK)
    except (Exception) as error:
        loggerError.error(f"Error in getOrganizationDetails : {str(error)}")
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# updateDetailsOfOrganization
#"updateDetailsOfOrga": ("public/updateOrganizationDetails/",profiles.updateDetailsOfOrganization)
#########################################################################
#TODO Add serializer for updateDetailsOfOrganization
#########################################################################
# Handler  
@extend_schema(
    summary="Update details of organization of that user.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn()
@api_view(["PATCH"])
@basics.checkIfRightsAreSufficient()
def updateDetailsOfOrganization(request:Request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    content = json.loads(request.body.decode("utf-8"))["data"]["content"]
    logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},details of {pgProfiles.ProfileManagementOrganization.getOrganization(request.session)[OrganizationDescription.name]}," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content)
    if flag is True:
        return Response("Success", status=status.HTTP_200_OK)
    else:
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# deleteOrganization
#"deleteOrganization": ("public/deleteOrganization/",profiles.deleteOrganization)
#########################################################################
#TODO Add serializer for deleteOrganization
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes an organization from the database and auth0.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn()
@api_view(["DELETE"])
@basics.checkIfRightsAreSufficient()
def deleteOrganization(request:Request):
    """
    Deletes an organization from the database and auth0.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    orgaID = pgProfiles.ProfileManagementOrganization.getOrganizationID(request.session)
    orgaName = pgProfiles.ProfileManagementOrganization.getOrganizationName(pgProfiles.ProfileManagementOrganization.getOrganizationHashID(request.session))
    flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
    if flag is True:
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}'
        }
        response = handleTooManyRequestsError( lambda : requests.delete(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers) )
        if isinstance(response, Exception):
            loggerError.error(f"Error deleting organization: {str(response)}")
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},organization {orgaName}," + str(datetime.datetime.now()))
        return Response("Success", status=status.HTTP_200_OK)
    else:
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# getUserDetails
#"getUser": ("public/getUser/",profiles.getUserDetails)
#########################################################################
#TODO Add serializer for getUserDetails
#########################################################################
# Handler  
@extend_schema(
    summary="Returns details about user.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@api_view(["GET"])
def getUserDetails(request:Request):
    """
    Return details about user. 

    :param request: GET request
    :type request: HTTP GET
    :return: User details
    :rtype: Json

    """
    # Read user details from Database
    try:
        userObj = pgProfiles.ProfileManagementBase.getUser(request.session)
        userObj[SessionContent.usertype] = request.session[SessionContent.usertype]
        # show only the current organization
        if pgProfiles.ProfileManagementBase.checkIfUserIsInOrganization(request.session):
            organizationsOfUser = userObj[UserDescription.organizations].split(",")
            del userObj[UserDescription.organizations]
            currentOrganizationOfUser = pgProfiles.ProfileManagementBase.getOrganization(request.session)
            for elem in organizationsOfUser:
                if elem == currentOrganizationOfUser[OrganizationDescription.hashedID]:
                    userObj["organization"] = elem
                    break
    except Exception as e:
        loggerError.error(f"Error getting user details: {str(e)}")
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return JsonResponse(userObj)

#########################################################################
# updateDetails
#"updateDetails": ("public/updateUserDetails/",profiles.updateDetails)
#########################################################################
#TODO Add serializer for updateDetails
#########################################################################
# Handler  
@extend_schema(
    summary="Updates user details.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn()
@api_view(["PATCH"])
def updateDetails(request:Request):
    """
    Update user details.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """

    content = json.loads(request.body.decode("utf-8"))
    logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.EDITED},updated,{Logging.Object.SELF},details," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content)
    if flag is True:
        return Response("Success", status=status.HTTP_200_OK)
    else:
        return HttpResponse("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# deleteUser
#"deleteUser": ("public/profileDeleteUser/",profiles.deleteUser)
#########################################################################
#TODO Add serializer for deleteUser
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes a user from the database and auth0.",
    description=" ",
    request=None,
    tags=['Profiles'],
    responses={
        200: None,
        500: ExceptionSerializer,
    },
)
@basics.checkIfUserIsLoggedIn()
@api_view(["DELETE"])
def deleteUser(request:Request):
    """
    Deletes a user from the database and auth0.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    # delete in database
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
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.SELF},," + str(datetime.datetime.now()))
        return Response("Success", status=status.HTTP_200_OK)
    else:
        return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
