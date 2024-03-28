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

from ..utilities import crypto
from ..connections.postgresql import pgProfiles
from ..utilities.basics import Logging, manualCheckifLoggedIn, manualCheckIfRightsAreSufficient, checkIfUserIsLoggedIn, checkIfRightsAreSufficient
from ..utilities.files import createFileResponse
from ..connections import s3

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

#######################################################################################
#######################################################
@require_http_methods(["POST"])
def genericUploadFiles(request):
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

        for fileName in fileNames:
            fileID = crypto.generateURLFriendlyRandomString()
            filePath = userName+"/"+fileID
            returnVal = s3.manageLocalS3.uploadFile(filePath, request.FILES.getlist(fileName)[0])
            if returnVal is not True:
                return HttpResponse("Failed", status=500)

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},uploaded,{Logging.Object.OBJECT},files,"+str(datetime.now()))
        return HttpResponse("Success")
    except (Exception) as error:
        loggerError.error(f"Error while uploading files: {str(error)}")
        return HttpResponse("Failed", status=500)

#######################################################
# TODO Transfer from local to remote
# implement in your more specific code!


#######################################################
@require_http_methods(["GET"])
def genericDownloadFile(request, fileID):
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

        # retrieve the correct file and download it from (local or remote) aws to the user
        content, Flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
        if Flag is False:
            content, Flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
            if Flag is False:
                return HttpResponse("Not found!", status=404)
            
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))
            
        return createFileResponse(content, filename=fileID)

    except (Exception) as error:
        loggerError.error(f"Error while downloading file: {str(error)}")
        return HttpResponse("Failed", status=500)

#######################################################
@require_http_methods(["GET"])
def genericDownloadFilesAsZip(request):
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

        # get files, download them from aws, put them in an array together with their name
        for fileID in fileIDs:
            content, Flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
            if Flag is False:
                content, Flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
                if Flag is False:
                    return HttpResponse("Not found!", status=404)
                
                filesArray.append( (fileID, content) )

        if len(filesArray) == 0:
            return HttpResponse("Not found!", status=404)
        
        # compress each file and put them in the same zip file, all in memory
        zipFile = BytesIO()
        with zipfile.ZipFile(zipFile, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in filesArray:
                zf.writestr(f[0], f[1].read())
        zipFile.seek(0) # reset zip file

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},files as zip," + str(datetime.now()))        
        return createFileResponse(zipFile, filename=userName+".zip")

    except (Exception) as error:
        loggerError.error(f"Error while downloading files as zip: {str(error)}")
        return HttpResponse("Failed", status=500)
    

#######################################################
@require_http_methods(["DELETE"])
def genericDeleteFile(request, fileID):
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
        
        returnVal = s3.manageLocalS3.deleteFile(userName+"/"+fileID)
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")
        returnVal = s3.manageRemoteS3.deleteFile(userName+"/"+fileID)
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))        
        return HttpResponse("Success", status=200)
    except (Exception) as error:
        loggerError.error(f"Error while deleting file: {str(error)}")
        return HttpResponse("Failed", status=500)
