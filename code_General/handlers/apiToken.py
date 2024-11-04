"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Handlers for handling the API Token
"""

import json, datetime, requests, logging, re

from django.views.decorators.http import require_http_methods

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.request import Request
from drf_spectacular.utils import extend_schema

from ..utilities import basics
from ..utilities.basics import ExceptionSerializerGeneric
from ..connections.postgresql import pgAPIToken

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

#######################################################
class SResAPIToken(serializers.Serializer):
    token = serializers.CharField(max_length=200, allow_blank=True)

#######################################################
@extend_schema(
    summary="Returns an existing API Token",
    description=" ",
    tags=['FE - Authentification'],
    request=None,
    responses={
        200: SResAPIToken,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["GET"])
@api_view(["GET"])
@basics.checkVersion(0.3)
def getAPIToken(request:Request):
    """
    Returns an existing API Token

    :param request: GET Request
    :type request: HTTP GET
    :return: JSON
    :rtype: JSON Response

    """
    try:
        apiToken = pgAPIToken.checkIfAPITokenExists(request.session)
        if isinstance(apiToken, Exception):
            raise apiToken
        # obfuscate token
        tokenLength = len(apiToken)
        apiToken = apiToken[:5] + "*"*(tokenLength - 5)
        outSerializer = SResAPIToken(data={"token": apiToken})
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except (Exception) as error:
        message = f"Error in {getAPIToken.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#######################################################
@extend_schema(
    summary="Generate a new API Token, thus deleting the old",
    description=" ",
    tags=['FE - Authentification'],
    request=None,
    responses={
        200: SResAPIToken,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["POST"])
@api_view(["POST"])
@basics.checkVersion(0.3)
def generateAPIToken(request:Request):
    """
    Generate a new API Token, thus deleting the old

    :param request: POST Request
    :type request: HTTP POST
    :return: Http Response
    :rtype: HttpResponse

    """
    try:
        apiToken = pgAPIToken.checkIfAPITokenExists(request.session)
        if isinstance(apiToken,Exception):
            raise apiToken
        error = pgAPIToken.deleteAPIToken(apiToken)
        if isinstance(error,Exception):
            raise error
        apiToken = pgAPIToken.createAPIToken(request.session)
        outSerializer = SResAPIToken(data={"token": apiToken})
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except (Exception) as error:
        message = f"Error in {generateAPIToken.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       

#######################################################
@extend_schema(
    summary="Deleted an API Token",
    description=" ",
    tags=['FE - Authentification'],
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
@basics.checkVersion(0.3)
def deleteAPIToken(request:Request):
    """
    Deleted an API Token

    :param request: DELETE Request
    :type request: HTTP DELETE
    :return: Success or not
    :rtype: HttpResponse

   """
    try:
        apiToken = pgAPIToken.checkIfAPITokenExists(request.session)
        if isinstance(apiToken, Exception):
            raise apiToken
        if apiToken != "":
            result = pgAPIToken.deleteAPIToken(apiToken)
            if isinstance(result, Exception):
                raise result
        return Response("Success", status=status.HTTP_200_OK)
    except (Exception) as error:
        message = f"Error in {deleteAPIToken.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)