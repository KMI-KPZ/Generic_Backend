"""
Part of Semper-KI software

Silvio Weging 2023

Contains: File upload handling
"""

import logging, zipfile
from io import BytesIO
from datetime import datetime

from django.http import HttpResponse
from django.views.decorators.http import require_http_methods

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema

from ..utilities import crypto
from ..definitions import Logging
from ..connections.postgresql import pgProfiles
from ..utilities.basics import manualCheckifLoggedIn, manualCheckIfRightsAreSufficient, checkIfUserIsLoggedIn, checkIfRightsAreSufficient, ExceptionSerializerGeneric
from ..utilities.files import createFileResponse
from ..connections import s3
from ..logics.filesLogics import *


logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

#######################################################################################

#########################################################################
# genericUploadFiles
#"genericUploadFiles": ("private/genericUploadFiles/",files.genericUploadFiles)
#########################################################################
#TODO Add serializer for genericUploadFiles
#########################################################################
# Handler  
@extend_schema(
    summary="Generic file upload",
    description=" ",
    request=None,
    tags=['FE - Files'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@api_view(["POST"])
def genericUploadFiles(request:Request):
    """
    Generic file upload

    :param request: Request with files in it
    :type request: HTTP POST
    :return: Successful or not
    :rtype: HTTP Response
    """
    try:
        exception, value = logicForGenericUploadFiles(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Sucess", status=status.HTTP_200_OK)
    
    except (Exception) as error:
        message = f"Error in {genericUploadFiles.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#######################################################
# TODO Transfer from local to remote
# implement in your more specific code!

#########################################################################
# genericDownloadFile
#"genericDownloadFile": ("private/genericDownloadFile/",files.genericDownloadFile)
#########################################################################
#TODO Add serializer for genericDownloadFile
#########################################################################
# Handler  
@extend_schema(
    summary="Generic file download",
    description=" ",
    request=None,
    tags=['FE - Files'],
    responses={
        200: None,
        404: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@api_view(["GET"])
def genericDownloadFile(request:Request, fileID):
    """
    Send file to user from storage

    :param request: Request of user for a specific file
    :type request: HTTP POST
    :param fileID: file ID
    :type fileID: Str
    :return: Saved content
    :rtype: FileResponse

    """
    try:
        content, exception, value = logicForGenericDownloadFile(fileID, request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   
        return createFileResponse(content, filename=fileID)

    except (Exception) as error:
        message = f"Error in {genericDownloadFile.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# genericDownloadFilesAsZip
#"genericDownloadFilesAsZip": ("private/genericDownloadFilesAsZip/",files.genericDownloadFilesAsZip)
#########################################################################
#TODO Add serializer for genericDownloadFilesAsZip
#########################################################################
# Handler  
@extend_schema(
    summary="Generic file download as zip",
    description=" ",
    request=None,
    tags=['FE - Files'],
    responses={
        200: None,
        404: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric,
    },
)
@api_view(["GET"])
def genericDownloadFilesAsZip(request:Request):
    """
    Send files to user as zip

    :param request: Request of user for all selected files
    :type request: HTTP POST
    :return: Saved content
    :rtype: FileResponse

    """
    try:
        userName, zipFile, exception, value = logicForGenericDeleteFile(request)
        
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return createFileResponse(zipFile, filename=userName+".zip")

    except (Exception) as error:
        message = f"Error in {genericDownloadFilesAsZip.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# genericDeleteFile
#"genericDeleteFile": ("private/genericDeleteFile/",files.genericDeleteFile)
#########################################################################
#TODO Add serializer for genericDeleteFile
#########################################################################
# Handler  
@extend_schema(
    summary="Generic file deletion",
    description=" ",
    request=None,
    tags=['FE - Files'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@api_view(["DELETE"])
def genericDeleteFile(request:Request, fileID):
    """
    Delete a file from storage

    :param request: Request of user for a specific file
    :type request: HTTP DELETE
    :param fileID: file ID
    :type fileID: Str
    :return: Successful or not
    :rtype: HTTPResponse

    """
    try:
        exception, value = logicForGenericDeleteFile(fileID, request)
        
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Sucess", status=status.HTTP_200_OK)

    except (Exception) as error:
        message = f"Error in {genericDeleteFile.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
