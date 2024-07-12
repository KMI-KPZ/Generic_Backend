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

from ..utilities import basics, crypto
from ..connections.postgresql import pgProfiles
from ..connections import auth0
from ..utilities.basics import handleTooManyRequestsError, ExceptionSerializerGeneric
from ..definitions import *

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
    tags=['Test'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
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
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
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
    tags=['FE - Profiles'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
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
        else:
            del userObj[UserDescription.organizations] # users who logged in as users don't need the organization info leaked
        
        # parse addresses 
        if basics.checkIfNestedKeyExists(userObj, UserDescription.details, UserDetails.addresses):
            userObj[UserDescription.details][UserDetails.addresses] = list(userObj[UserDescription.details][UserDetails.addresses].values())
        
        return Response(userObj, status=status.HTTP_200_OK)
    
    except Exception as error:
        message = f"Error in {getUserDetails.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    

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
    tags=['FE - Profiles'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
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
    try:
        content = json.loads(request.body.decode("utf-8"))
        # TODO serializers and validation
        if "changes" in content:
            flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content["changes"])
            if isinstance(flag, Exception):
                raise flag
        if "deletions" in content:
            flag = pgProfiles.ProfileManagementUser.deleteContent(request.session, content["deletions"])
            if isinstance(flag, Exception):
                raise flag
        
        logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.EDITED},updated,{Logging.Object.SELF},details," + str(datetime.datetime.now()))
        return Response("Success", status=status.HTTP_200_OK)

    except (Exception) as error:
        message = f"Error in {updateDetails.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
##############################################
#######################################################
class SReqNewAddress(serializers.Serializer):
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
@extend_schema(
    summary="Create new address for user",
    description=" ",
    tags=['FE - Profiles'],
    request=SReqNewAddress,
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["POST"])
@api_view(["POST"])
def createAddress(request:Request):
    """
    Create new address for user

    :param request: POST Request
    :type request: HTTP POST
    :return: Success or not
    :rtype: Response

    """
    try:
        inSerializer = SReqNewAddress(data=request.data)
        if not inSerializer.is_valid():
            message = f"Creating address failed in {createAddress.cls.__name__}"
            exception = "Creation of address failed"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        address = inSerializer.data
        setToStandardAddress = address["standard"] # if the new address will be the standard address
        userObj = pgProfiles.ProfileManagementBase.getUser(request.session) #deepcopy not necessary as changes to this dict are not saved
        newContentInDB = {UserDetails.addresses: {}}
        if UserDetails.addresses in userObj[UserDescription.details]: # add old content
            newContentInDB[UserDetails.addresses] = userObj[UserDescription.details][UserDetails.addresses]
            if setToStandardAddress:
                for key in newContentInDB[UserDetails.addresses]:
                    newContentInDB[UserDetails.addresses][key]["standard"] = False

        # add new content
        idForNewAddress = crypto.generateURLFriendlyRandomString()
        address["id"] = idForNewAddress
        newContentInDB[UserDetails.addresses][idForNewAddress] = address
        logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{Logging.Predicate.EDITED},updated,{Logging.Object.SELF},details," + str(datetime.datetime.now()))
        flag = pgProfiles.ProfileManagementUser.updateContent(request.session, newContentInDB, UserDescription.details)
        if flag is True:
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except (Exception) as error:
        message = f"Error in {createAddress.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#######################################################
class SReqUpdateContent(serializers.Serializer):
    id = serializers.CharField(max_length=200)
    firstName = serializers.CharField(max_length=200)
    lastName = serializers.CharField(max_length=200)
    company = serializers.CharField(max_length=200, required=False, default="", allow_blank=True)
    street = serializers.CharField(max_length=200)
    houseNumber = serializers.IntegerField()
    zipcode = serializers.CharField(max_length=200)
    city = serializers.CharField(max_length=200)
    country = serializers.CharField(max_length=200)
    standard = serializers.BooleanField()
#######################################################
@extend_schema(
    summary="Changes content of an address",
    description=" ",
    tags=['FE - Profiles'],
    request=SReqUpdateContent,
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        404: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["PATCH"])
@api_view(["PATCH"])
def updateAddress(request:Request):
    """
    Changes content of an address

    :param request: PATCH Request
    :type request: HTTP PATCH
    :return: Success or not
    :rtype: Response

    """
    try:
        inSerializer = SReqUpdateContent(data=request.data)
        if not inSerializer.is_valid():
            message = f"Updating address failed in {updateAddress.cls.__name__}"
            exception = "Updating the address failed"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        address = inSerializer.data
        setToStandardAddress = address["standard"] # if the new one will be the new standard address or not
        existingAddresses = pgProfiles.ProfileManagementBase.getUser(request.session)[UserDescription.details][UserDetails.addresses]
    
        if address["id"] in existingAddresses:
            if setToStandardAddress: # set all others to False for not being the standard address anymore
                for key in existingAddresses:
                    existingAddresses[key]["standard"] = False

            existingAddresses[address["id"]] = address
            flag = pgProfiles.ProfileManagementUser.updateContent(request.session, {UserDetails.addresses: existingAddresses}, UserDescription.details)
            if flag is True:
                return Response("Success", status=status.HTTP_200_OK)
            else:
                return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response("Failed", status=status.HTTP_404_NOT_FOUND)

    except (Exception) as error:
        message = f"Error in {updateAddress.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#######################################################
@extend_schema(
    summary="Remove an address for a user",
    description=" ",
    tags=['FE - Profiles'],
    request=None,
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["DELETE"])
@api_view(["DELETE"])
def deleteAddress(request:Request,addressID:str):
    """
    Remove an address for a user

    :param request: DELETE Request
    :type request: HTTP DELETE
    :return: Success or not
    :rtype: Response

    """
    try:
        existingAddresses = pgProfiles.ProfileManagementBase.getUser(request.session)[UserDescription.details][UserDetails.addresses]
        if addressID in existingAddresses:
            del existingAddresses[addressID]
            flag = pgProfiles.ProfileManagementUser.updateContent(request.session, {UserDetails.addresses: existingAddresses}, UserDescription.details)
            if flag is True:
                return Response("Success", status=status.HTTP_200_OK)
            else:
                return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response("Failed", status=status.HTTP_404_NOT_FOUND)
        
    except (Exception) as error:
        message = f"Error in {deleteAddress.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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
    tags=['FE - Profiles'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
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
    try:
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
    except (Exception) as error:
        message = f"Error in {deleteUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
