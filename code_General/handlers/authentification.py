"""
Generic Backend

Silvio Weging 2023

Contains: Authentification handling using Auth0
"""

import json, datetime, requests, logging, re
from urllib.parse import quote_plus, urlencode

from django.views.decorators.csrf import ensure_csrf_cookie
from django.conf import settings
from django.urls import reverse
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from rest_framework.request import Request
from drf_spectacular.utils import extend_schema
from drf_spectacular.utils import OpenApiParameter, inline_serializer

from ..utilities import basics, rights, signals, mocks
from ..utilities.basics import ExceptionSerializerGeneric
from ..connections.postgresql import pgProfiles
from ..connections import auth0, redis
from ..definitions import Logging, SessionContent, ProfileClasses, UserDescription

from ..logics.authenticationLogics import *

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

#######################################################

###################################################
# CSRF protection
#@csrf_protect
@extend_schema(
    summary="Ensures that the csrf cookie is set correctly.",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,  
    },
)
@ensure_csrf_cookie
@api_view(['GET'])
def createCsrfCookie(request:Request):
    """
    Ensures that the csrf cookie is set correctly.

    :param request: GET request
    :type request: HTTP GET
    :return: Response with cookie
    :rtype: HTTP Response

    """
    try:
        response = Response("CSRF cookie set", status=status.HTTP_200_OK)
        return response
    except (Exception) as error:
        message = f"Error in {createCsrfCookie.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# isLoggedIn
#"isLoggedIn": ("public/isLoggedIn/",authentification.isLoggedIn)
#########################################################################
#TODO Add serializer for isLoggedIn
#########################################################################
# Handler  
@extend_schema(
    summary="Check whether the token of a user has expired and a new login is necessary",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric
    },
)
@api_view(["GET"])
def isLoggedIn(request:Request):
    """
    Check whether the token of a user has expired and a new login is necessary

    :param request: User session token
    :type request: Dictionary
    :return: True if the token is valid or False if not
    :rtype: HttpResponse
    """
    # Initialize session if not done already to generate session key
    if SessionContent.INITIALIZED not in request.session:
        request.session[SessionContent.INITIALIZED] = True

    # Check if user is already logged in
    if "user" in request.session:
        if basics.checkIfTokenValid(request.session["user"]):
            return Response("Success",status=status.HTTP_200_OK)
        else:
            return Response("Failed",status=status.HTTP_200_OK)
    
    return Response("Failed",status=status.HTTP_200_OK)

#########################################################################
# setLocaleOfUser
#"setLocaleOfUser": ("public/setLocaleOfUser/", authentification.setLocaleOfUser)
#########################################################################
#######################################################
class SReqLocale(serializers.Serializer):
    locale = serializers.CharField(max_length=200, default="de-DE")
#########################################################################
# Handler  
@extend_schema(
    summary="Get the preferred language of the user from the frontend .",
    description=" ",
    request=SReqLocale,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric
    },
)
@api_view(["POST"])
def setLocaleOfUser(request:Request):
    """
    Get the preferred language of the user from the frontend

    :param request: Information from the frontend
    :type request: Dictionary-like object (nonmutable)
    :return: Success if language could be saved in session, failed if not
    :rtype: HttpResponse
    
    """
    try:
        # Initialize session if not done already to generate session key
        if SessionContent.INITIALIZED not in request.session:
            request.session[SessionContent.INITIALIZED] = True
        
        inSerializer = SReqLocale(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {setLocaleOfUser.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            loggerError.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        exception, value = logicForSetLocaleOfUser(validatedInput, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response("Success",status=status.HTTP_200_OK)
    
    except Exception as error:
        message = f"Error in {setLocaleOfUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#########################################################################
# provideRightsFile
#"getPermissionsFile": ("public/getPermissionMask/",authentification.provideRightsFile)
#########################################################################
#TODO Add serializer for provideRightsFile
#########################################################################
# Handler  
@extend_schema(
    summary="Returns the json file containing the rights for the frontend",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric
    },
)
@api_view(["GET"])
@basics.checkIfUserIsLoggedIn(json=True)
def provideRightsFile(request:Request):
    """
    Returns the json file containing the rights for the frontend

    :param request: GET request
    :type request: HTTP GET
    :return: JSON Response.
    :rtype: JSONResponse

    """
    
    return Response(rights.rightsManagement.getFile())


#######################################################
@extend_schema(
    summary="Use fakeUser, fakeOrganization or fakeAdmin to log in from the swagger interface",
    description=" ",
    tags=['BE - Authentification'],
    request=None,
    parameters=[OpenApiParameter(
        name='Usertype',
        type={'type': 'string'},
        location=OpenApiParameter.HEADER,
    )],
    responses={
        200: None,
        500: ExceptionSerializerGeneric
    }
)
@api_view(["GET"])
def loginAsTestUser(request:Request):
    """
    Use fakeUser, fakeOrganization or fakeAdmin to log in from the swagger interface.

    :param request: GET Request
    :type request: HTTP GET
    :return: Nothing
    :rtype: None

    """
    try:
        loginUser(request._request)
        callbackLogin(request._request)
        return Response("Success", status=status.HTTP_200_OK)

    except (Exception) as error:
        message = f"Error in {loginAsTestUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# loginUser
#"login" : ("public/login/",authentification.loginUser)
#########################################################################
#TODO Add serializer for loginUser
#########################################################################
# Handler  
@extend_schema(
    summary="Return a link for redirection to Auth0",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@api_view(["GET"])
def loginUser(request:Request):
    """
    Return a link for redirection to Auth0.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP Response.
    :rtype: HTTP Link as str

    """
    try:
        outputOrException, statusCode = logicForLoginUser(request)
        if isinstance(outputOrException, Exception):
            message = str(outputOrException)
            loggerError.error(outputOrException)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": outputOrException})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=statusCode)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(outputOrException)

    except Exception as error:
        message = f"Error in {loginUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# callbackLogin
#"callbackLogin": ("public/callback/",authentification.callbackLogin)
#########################################################################
#TODO Add serializer for callbackLogin
#########################################################################
# Handler  
@extend_schema(
    summary="Check if user really is part of an organization or not",
    description="check if misclick at login, and set flags and instances here.  Get information back from Auth0.  Add user to database if entry doesn't exist. ",
    request=None,
    tags=['BE - Authentification'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@api_view(["POST" ,"GET"])
def callbackLogin(request:Request):
    """
    TODO: Check if user really is part of an organization or not -> check if misclick at login, and set flags and instances here
    Get information back from Auth0.
    Add user to database if entry doesn't exist.

    :param request: POST request
    :type request: HTTP POST
    :return: URL forwarding with success to frontend/user
    :rtype: HTTP Link as redirect

    """
    try:
        output, exception, value = logicForCallbackLogin(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            returnObj = HttpResponseRedirect(output, status=value)
            returnObj.write(message)
            return returnObj
        else:
            # possibly check if Path in output is indeed viable
            return HttpResponseRedirect(output)

    except Exception as e:
        returnObj = HttpResponseRedirect(request.session[SessionContent.PATH_AFTER_LOGIN])
        returnObj.write(str(e))
        return returnObj

#########################################################################
# getRolesOfUser
#"getRoles": ("public/getRoles/",authentification.getRolesOfUser)
#########################################################################
#TODO Add serializer for getRolesOfUser
#########################################################################
# Handler  
@extend_schema(
    summary=" Get Roles of User.",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: serializers.ListSerializer(child=serializers.CharField()),
        400: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@api_view(["GET"])
def getRolesOfUser(request:Request):
    """
    Get Roles of User.

    :param request: GET request
    :type request: HTTP GET
    :return: List of roles
    :rtype: JSONResponse
    """
    try:
        output, exception, value = logicForGetRolesOfUser(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            if output == []:
                return Response([], status=status.HTTP_200_OK)
            else:
                if output is not None:
                    outSerializer = serializers.ListSerializer(child=serializers.CharField(), data=output)
                    if outSerializer.is_valid():
                        return Response(outSerializer.data, status=status.HTTP_200_OK)
                    else:
                        raise Exception(outSerializer.errors)

    except (Exception) as error:
        message = f"Error in {getRolesOfUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# getPermissionsOfUser
#"getPermissions": ("public/getPermissions/",authentification.getPermissionsOfUser)
#########################################################################
#######################################################
class SResPermissionsOfUser(serializers.Serializer):
    context = serializers.CharField(max_length=200)
    permission = serializers.CharField(max_length=200)
#########################################################################
# Handler  
@extend_schema(
    summary="Get Permissions of User.",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: serializers.ListSerializer(child=SResPermissionsOfUser()),
        400: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@api_view(["GET"])
def getPermissionsOfUser(request:Request):
    """
    Get Permissions of User.

    :param request: GET request
    :type request: HTTP GET
    :return: List of roles
    :rtype: JSONResponse
    """
    try:
        output, exception, value = logicForGetPermissionsOfUser(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            if output == []:
                return Response([], status=status.HTTP_200_OK)
            else:
                if output is not None:
                    outSerializer = serializers.ListSerializer(child=SResPermissionsOfUser(), data=output)
                    if outSerializer.is_valid():
                        return Response(outSerializer.data, status=status.HTTP_200_OK)
                    else:
                        raise Exception(outSerializer.errors)

    except (Exception) as error:
        message = f"Error in {getPermissionsOfUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# getNewRoleAndPermissionsForUser
#"getNewPermissions": ("public/getNewPermissions/",authentification.getNewRoleAndPermissionsForUser)
#########################################################################
#TODO Add serializer for getNewRoleAndPermissionsForUser
#########################################################################
# Handler  
@extend_schema(
    summary="In case the role changed, get new role and new permissions from auth0.",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: serializers.ListSerializer(child=SResPermissionsOfUser()),
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@api_view(["GET"])
def getNewRoleAndPermissionsForUser(request:Request):
    """
    In case the role changed, get new role and new permissions from auth0

    :param request: GET request
    :type request: HTTP GET
    :return: If successfull or not
    :rtype: Bool
    """
    try:
        retVal = setRoleAndPermissionsOfUser(request)
        if isinstance(retVal, Exception):
            return Response(retVal, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return getPermissionsOfUser(request._request)
    except (Exception) as error:
        message = f"Error in {getNewRoleAndPermissionsForUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      

#########################################################################
# logoutUser
#"logout": ("public/logout/",authentification.logoutUser)
#########################################################################
#TODO Add serializer for logoutUser
#########################################################################
# Handler  
@extend_schema(
    summary="Delete session for this user and log out.",
    description=" ",
    request=None,
    tags=['FE - Authentification'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric
    },
)
@api_view(["GET"])
def logoutUser(request:Request):
    """
    Delete session for this user and log out.

    :param request: GET request
    :type request: HTTP GET
    :return: URL to be forwarded
    :rtype: HTTP URL

    """
    try:
        output, exception, value = logicForLogoutUser(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(output, status=value)

    except Exception as error:
        message = f"Error in {logoutUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
