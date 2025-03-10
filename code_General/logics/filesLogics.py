"""
Generic Backend

Silvio Weging 2024

Contains: Logic for Files
"""
import os
import logging
import zipfile
import base64

from io import BytesIO
from datetime import datetime
from boto3.s3.transfer import TransferConfig

from ..utilities import crypto
from ..definitions import *
from ..connections.postgresql import pgProfiles, pgEvents
from ..utilities.createFilePreviews import createAndStorePreview
from ..connections import s3

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForGenericUploadFiles(request):
    """
    Generic file upload
    
    """
    try:
        fileNames = list(request.FILES.keys())
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        locale = pgProfiles.ProfileManagementBase.getUserLocale(request.session)
        assert isinstance(userName, str), f"In {logicForGenericUploadFiles.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericUploadFiles.__name__}: non-empty userName expected"

        # check if duplicates exist
        existingFileNames = set()
        # fill existingFileNames somehow

        for fileName in fileNames:
            # rename duplicates
            counterForFileName = 1
            nameOfFile = fileName
            while nameOfFile in existingFileNames:
                fileNameRoot, extension= os.path.splitext(nameOfFile)
                if counterForFileName > 100000:
                    raise Exception("Too many files with the same name uploaded!")
                
                if "_" in fileNameRoot:
                    fileNameRootSplit = fileNameRoot.split("_")
                    try:
                        counterForFileName = int(fileNameRootSplit[-1])
                        fileNameRoot = "_".join(fileNameRootSplit[:-1])
                        counterForFileName += 1
                    except:
                        pass
                nameOfFile = fileNameRoot + "_" + str(counterForFileName) + extension
                counterForFileName += 1
        
            for file in request.FILES.getlist(fileName):
                fileID = crypto.generateURLFriendlyRandomString()
                assert isinstance(fileID, str), f"In {logicForGenericUploadFiles.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
                assert fileID != "", f"In {logicForGenericUploadFiles.__name__}: non-empty fileID expected"
                filePath = userName+"/"+fileID
                # generate preview
                previewPath = createAndStorePreview(file, nameOfFile, locale, filePath)
                if isinstance(previewPath, Exception):
                    raise previewPath
                # TODO store somewhere with some information

                # determine where to upload the file (remote or local, currently only local)
                returnVal = s3.manageLocalS3.uploadFile(filePath, file)
                assert isinstance(returnVal, bool), f"In {logicForGenericUploadFiles.__name__}: expected returnVal to be of type bool, instead got: {type(returnVal)}"
                if returnVal is not True:
                    #return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    return (Exception("Failed"), 500)
            
        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.CREATED},uploaded,{Logging.Object.OBJECT},files,"+str(datetime.now()))
        return (None, 200)
    
    except Exception as e:
        return (e, 500)
    
#######################################################
def moveFileToRemote(fileKeyLocal, fileKeyRemote, deleteLocal = True) -> bool:
    """
    Move a file from local to remote storage with on the fly encryption not managing other information

    :param fileKeyLocal: The key with which to retrieve the file again later
    :type fileKeyLocal: Str
    :param fileKeyRemote: The key with which to retrieve the file again later
    :type fileKeyRemote: Str
    :param delteLocal: If set to True the local file will be deleted after the transfer
    :type delteLocal: bool
    :return: Success or error
    :rtype: Bool or Error

    """
    try:
        # try to retrieve it from local storage
        fileStreamingBody, flag = s3.manageLocalS3.getFileStreamingBody(fileKeyLocal)
        if flag is False:
            logger.warning(f"File {fileKeyLocal} not found in local storage to move to remote")
            return False

        config = TransferConfig(
            multipart_threshold=1024 * 1024 * 5,  # Upload files larger than 5 MB in multiple parts (default: 8 MB)
            max_concurrency=10,  # Use 10 threads for large files (default: 10, max 10)
            multipart_chunksize=1024 * 1024 * 5,  # 5 MB parts (min / default: 5 MB)
            use_threads=True  # allow threads for multipart upload
        )

        #setup encryption
        encryptionAdapter = crypto.EncryptionAdapter(fileStreamingBody)
        encryptionAdapter.setupEncryptOnRead(base64.b64decode(s3.manageRemoteS3.aesEncryptionKey))

        try :
            result = s3.manageRemoteS3.uploadFileObject(fileKeyRemote, encryptionAdapter, config)
            #TODO check if the file was uploaded successfully
        except Exception as e:
            logging.error(f"Error while uploading file {fileKeyLocal} from local to remote {fileKeyRemote}: {str(e)}")
            return False

        if deleteLocal:
            returnVal = s3.manageLocalS3.deleteFile(fileKeyLocal)
            if returnVal is not True:
                logging.error("Deletion of file" + fileKeyLocal + " failed")

        return True

    except Exception as error:
        loggerError.error(f"Error while moving file to remote: {str(error)}")
        return False
    
##############################################
def logicForGenericDownloadFile(fileID, request):
    """
    Generic file download

    """
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDownloadFile.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDownloadFile.__name__}: non-empty userName expected"

        # retrieve the correct file and download it from (local or remote) aws to the user
        assert isinstance(fileID, str), f"In {logicForGenericDownloadFile.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
        assert fileID != "", f"In {logicForGenericDownloadFile.__name__}: non-empty fileID expected" 
        # TODO better find out via flag if the file lies on remote or local storage
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
    """
    Generic file download as zip
    
    """
    try:
        fileIDs = request.GET['fileIDs'].split(",")

        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDownloadFilesAsZip.__name__}: non-empty userName expected"

        # compress each file and put them in the same zip file, all in memory
        zipFile = BytesIO()
        with zipfile.ZipFile(zipFile, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            # get files, download them from storage, put them in an array together with their name
            for fileID in fileIDs:
                assert isinstance(fileID, str), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected fileID to be of type string, instead got: {type(fileID)}"
                assert fileID != "", f"In {logicForGenericDownloadFilesAsZip.__name__}: non-empty fileID expected"
                # TODO better find out via flag if the file lies on remote or local storage
                content, flag = s3.manageLocalS3.downloadFile(userName+"/"+fileID)
                assert isinstance(flag, bool), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
                if flag is False:
                    content, flag = s3.manageRemoteS3.downloadFile(userName+"/"+fileID)
                    assert isinstance(flag, bool), f"In {logicForGenericDownloadFilesAsZip.__name__}: expected userName to be of type bool, instead got: {type(flag)}"
                    if flag is False:
                        #return Response("Not found!", status=status.HTTP_404_NOT_FOUND)
                        return (None, None, Exception("Not found!"), 404)
                
                zf.writestr(fileID, content.read())
                
        zipFile.seek(0) # reset zip file

        logger.info(f"{Logging.Subject.USER},{userName},{Logging.Predicate.FETCHED},downloaded,{Logging.Object.OBJECT},files as zip," + str(datetime.now()))
        return (userName, zipFile, None, 200)
    
    except Exception as e:
        return (None, None, e, 500)
        

##############################################
def logicForGenericDeleteFile(fileID, request):
    """
    Generic file delete
    
    """
    try:
        userName = pgProfiles.ProfileManagementBase.getUserName(request.session)
        assert isinstance(userName, str), f"In {logicForGenericDeleteFile.__name__}: expected userName to be of type string, instead got: {type(userName)}"
        assert userName != "", f"In {logicForGenericDeleteFile.__name__}: non-empty userName expected"

        # TODO better find out via flag if the file lies on remote or local storage
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