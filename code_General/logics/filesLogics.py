"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for Files
"""
from io import BytesIO
import logging
from datetime import datetime
import zipfile

from Generic_Backend.code_General.utilities import crypto

from ..definitions import *
from ..connections.postgresql import pgProfiles, pgEvents

from ..connections import s3


from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForGenericUploadFiles(request):
    try:
        fileNames = list(request.FILES.keys())
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericUploadFiles.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericUploadFiles.__name__}: non-empty userName expected"

        for fileName in fileNames:
            fileID = crypto.generateURLFriendlyRandomString()
            assert isinstance(fileID, str), f"In {logicForGenericUploadFiles.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
            assert fileID != "", f"In {logicForGenericUploadFiles.__name__}: non-empty fileID expected"
            filePath = userName+"/"+fileID
            returnVal = s3.manageLocalS3.uploadFile(filePath, request.FILES.getlist(fileName)[0])
            assert isinstance(returnVal, bool), f"In {logicForGenericUploadFiles.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}"
            if returnVal is not True:
                #return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return (Exception("Failed"), 500)
            
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},uploaded,{Logging.Object.OBJECT},files,"+str(datetime.now()))
        return (None, 200)
    
    except Exception as e:
        return (e, 500)
    
##############################################
def logicForGenericDownloadFile(fileID, request):
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDownloadFile.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDownloadFile.__name__}: non-empty userName expected"

        # retrieve the correct file and download it from (local or remote) aws to the user
        assert isinstance(fileID, str), f"In {logicForGenericDownloadFile.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
        assert fileID != "", f"In {logicForGenericDownloadFile.__name__}: non-empty fileID expected" 
        content, flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
        assert isinstance(flag, bool), f"In {logicForGenericDownloadFile.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
        if flag is False:
            content, flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
            assert isinstance(flag, bool), f"In {logicForGenericDownloadFile.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
            if flag is False:
                #return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
                return (None, Exception("Not found!"), 404)
            
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))
        return (content, None, 200)
    except Exception as e:
        return (None, e, 500)

##############################################
def logicForGenericDownloadFilesAsZip(request):
    try:
        fileIDs = request.GET['fileIDs'].split(",")
        filesArray = []

        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDownloadFilesAsZip.__name__}: non-empty userName expected"

        # get files, download them from aws, put them in an array together with their name
        for fileID in fileIDs:
            assert isinstance(fileID, str), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
            assert fileID != "", f"In {logicForGenericDownloadFilesAsZip.__name__}: non-empty fileID expected"
            content, flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
            assert isinstance(flag, bool), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
            if flag is False:
                content, flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
                assert isinstance(flag, bool), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
                if flag is False:
                    #return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
                    return (None, None, Exception("Not found!"), 404)
                
                filesArray.append( (fileID, content) )

        if len(filesArray) == 0:
            #return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
            return (None, None, Exception("Not found!"), 404)

        
        # compress each file and put them in the same zip file, all in memory
        zipFile = BytesIO()
        with zipfile.ZipFile(zipFile, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in filesArray:
                zf.writestr(f[0], f[1].read())
        zipFile.seek(0) # reset zip file

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},files as zip," + str(datetime.now()))
        return (userName, zipFile, None, 200)
    
    except Exception as e:
        return (None, None, e, 500)
        

##############################################
def logicForGenericDeleteFile(fileID, request):
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDeleteFile.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDeleteFile.__name__}: non-empty userName expected"

        returnVal = s3.manageLocalS3.deleteFile(userName+"/"+fileID)
        assert isinstance(returnVal, bool), f"In {logicForGenericDeleteFile.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}" #might need to be adjusted when deleteFile gets updated
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")
        returnVal = s3.manageRemoteS3.deleteFile(userName+"/"+fileID)
        assert isinstance(returnVal, bool), f"In {logicForGenericDeleteFile.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}" #might need to be adjusted when deleteFile gets updated
        if returnVal is not True:
            raise Exception("Deletion of file" + fileID + " failed")

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.DELETED},deleted,{Logging.Object.OBJECT},file {fileID}," + str(datetime.now()))        
        return (None, 200)
    except Exception as e:
        return (e, 500)