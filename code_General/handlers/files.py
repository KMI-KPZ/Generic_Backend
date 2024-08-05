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
        fileNames = list(request.FILES.keys())
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {genericUploadFiles.cls.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {genericUploadFiles.cls.__name__}: non-empty userName expected"

        for fileName in fileNames:
            fileID = crypto.generateURLFriendlyRandomString()
            assert isinstance(fileID, str), f"In {genericUploadFiles.cls.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
            assert fileID != "", f"In {genericUploadFiles.cls.__name__}: non-empty fileID expected"
            filePath = userName+"/"+fileID
            returnVal = s3.manageLocalS3.uploadFile(filePath, request.FILES.getlist(fileName)[0])
            assert isinstance(returnVal, bool), f"In {genericUploadFiles.cls.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}"
            if returnVal is not True:
                return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},uploaded,{Logging.Object.OBJECT},files,"+str(datetime.now()))
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
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {genericDownloadFile.cls.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {genericDownloadFile.cls.__name__}: non-empty userName expected"

        # retrieve the correct file and download it from (local or remote) aws to the user
        assert isinstance(fileID, str), f"In {genericDownloadFile.cls.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
        assert fileID != "", f"In {genericDownloadFile.cls.__name__}: non-empty fileID expected" 
        content, flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
        assert isinstance(flag, bool), f"In {genericDownloadFile.cls.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
        if flag is False:
            content, flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
            assert isinstance(flag, bool), f"In {genericDownloadFile.cls.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
            if flag is False:
                return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
            
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))
            
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
        fileIDs = request.GET['fileIDs'].split(",")
        filesArray = []

        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {genericDownloadFilesAsZip.cls.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {genericDownloadFilesAsZip.cls.__name__}: non-empty userName expected"

        # get files, download them from aws, put them in an array together with their name
        for fileID in fileIDs:
            assert isinstance(fileID, str), f"In {genericDownloadFilesAsZip.cls.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
            assert fileID != "", f"In {genericDownloadFilesAsZip.cls.__name__}: non-empty fileID expected"
            content, flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
            assert isinstance(flag, bool), f"In {genericDownloadFilesAsZip.cls.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
            if flag is False:
                content, flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
                assert isinstance(flag, bool), f"In {genericDownloadFilesAsZip.cls.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
                if flag is False:
                    return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
                
                filesArray.append( (fileID, content) )

        if len(filesArray) == 0:
            return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
        
        # compress each file and put them in the same zip file, all in memory
        zipFile = BytesIO()
        with zipfile.ZipFile(zipFile, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in filesArray:
                zf.writestr(f[0], f[1].read())
        zipFile.seek(0) # reset zip file

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},files as zip," + str(datetime.now()))        
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

        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {genericDeleteFile.cls.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {genericDeleteFile.cls.__name__}: non-empty userName expected"

        returnVal = s3.manageLocalS3.deleteFile(userName+"/"+fileID)
        assert isinstance(returnVal, bool), f"In {genericDeleteFile.cls.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}" #might need to be adjusted when deleteFile gets updated
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")
        returnVal = s3.manageRemoteS3.deleteFile(userName+"/"+fileID)
        assert isinstance(returnVal, bool), f"In {genericDeleteFile.cls.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}" #might need to be adjusted when deleteFile gets updated
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))        
        return Response("Success", status=status.HTTP_200_OK)
    except (Exception) as error:
        message = f"Error in {genericDeleteFile.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
