"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for aws cloud storage and file management
"""
import logging

import boto3, enum
from io import BytesIO

from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from ..utilities import crypto

from django.conf import settings

#####################################################################
class ManageS3():
    """
    Class for managing access to local/remote AWS

    """


    #######################################################
    def __getattr__(self, item):
        """
        Lazy loading of the boto client. Is stored in a function object that is called in __getattr__

        :param item: the attribute to get
        :type item: str
        :return: the attribute
        :rtype: object
        """

        if item == "s3_client":
            self.s3_client = self.initClient()
            if self.local:
                self.createBucket(self.bucketName) # has to be done every time lest minio forgets it exists
            return self.s3_client
        if item == "s3_resource":
            self.s3_resource = self.initResource()
            return self.s3_resource
        else:
            raise AttributeError

    #######################################################
    def __init__(self, aesKey, location, bucketName, endpoint, key, secret, local:bool, downloadLinkPrefix) -> None:
        """
        Initialize instance with settings for either local or remote storage

        :param endpoint: IP Address of storage
        :type endpoint: URL Str
        :param key: The access key
        :type key: Str
        :param secret: The secret/password
        :type secret: Str
        """
        # lazy loading of the boto client. Is stored in a function object that is called in __getattr__
        self.initClient = lambda : boto3.client("s3", region_name=location, endpoint_url=endpoint, aws_access_key_id=key, aws_secret_access_key=secret)
        self.initResource = lambda : boto3.resource("s3", region_name=location, endpoint_url=endpoint, aws_access_key_id=key, aws_secret_access_key=secret)
        self.bucketName = bucketName
        self.aesEncryptionKey = aesKey
        self.local = local
        self.downloadLinkPrefix = downloadLinkPrefix

    #######################################################
    def createBucket(self, bucketName):
        """
        Create a named bucket to put stuff in. Should only be used freely for minio!

        :param bucketName: Name of the bucket
        :type bucketName: Str
        :return: Success or error
        :rtype: Bool or Error
        """
        try:
            self.s3_client.head_bucket(Bucket=bucketName)
        except:
            response = self.s3_client.create_bucket(ACL='private', Bucket=bucketName)
            # TODO if response...

        return True
    
    #######################################################
    def uploadFile(self, fileKey, file):
        """
        Upload a binary in-memory file to storage.

        :param fileKey: The key with which to retrieve the file again later
        :type fileKey: Str
        :param file: InMemory BytesIO object containing a file
        :type file: BytesIO InMemoryFile
        :return: Success or error
        :rtype: Bool or Error
        """
        # see if file.file exists and set file to file.file if it does
        if hasattr(file, 'file'):
            file = file.file

        file.seek(0) # because read() is called and has to start at the front of the file
        fileToBeUploaded = file
        if self.local is False:
            fileToBeUploaded = crypto.encryptAES(self.aesEncryptionKey, file) # encrypt file for remote AWS
        response = self.s3_client.upload_fileobj(fileToBeUploaded, self.bucketName, fileKey)
        # TODO if response...

        return True


    #######################################################
    def uploadFileObject(self, fileKey, file, config = None):
        """
        Upload a binary in-memory file like object to storage.
        :param fileKey: the key with which to retrieve the file again later
        :type fileKey: str
        :param file: the file like object to be uploaded - should have a read method
        :type file: object
        :param config: the configuration for the upload (see boto3 documentation)
        :type config: dict
        :return: Pass through of the boto3 upload_fileobj response
        :rtype: dict
        """
        return self.s3_client.upload_fileobj(file, self.bucketName, fileKey, Config=config)


    #######################################################
    def downloadFile(self, fileKey) -> tuple[BytesIO, bool]:
        """
        Download a binary in-memory file to storage.

        :param fileKey: The key with which to retrieve the file again later
        :type fileKey: Str
        :return: File or error
        :rtype: BytesIO or Error
        """

        output = BytesIO()
        try:
            self.s3_client.download_fileobj(self.bucketName, fileKey, output)
        except Exception as e:
            logging.warning(f"Error while downloading file: {str(e)}")
            return (output, False)

        output.seek(0)
        if output.getbuffer().nbytes == 0: # is empty so no file has been downloaded
            return (output, False)
        if self.local is False: # remote aws files are encrypted
            decrypted_file = crypto.decryptAES(self.aesEncryptionKey, output)
            return (decrypted_file, True)
        else:
            return (output, True)


    #######################################################
    def getFileObject(self, fileKey) :
        """
        Get the file object from storage.

        :param fileKey: The key with which to retrieve the file again later in combination with the bucket name
        :type fileKey: Str
        :return: ( FileObject or None , true if successful)
        :rtype: ( object, bool )

        """

        try:
            result = self.s3_client.get_object(Bucket=self.bucketName,Key=fileKey)
            return (result, True)
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchKey":
                logging.info(f"file does not exist: {str(e)}")
                return (None, False)
            logging.warning(f"Error while accessing file {fileKey}: {str(e)}")
            return (None, False)


    #######################################################
    def getFileStreamingBody(self, fileKey) -> tuple[StreamingBody, bool]:
        """
        Get the file object stream from storage.

        :param fileKey: the key with which to retrieve the file again later
        :type fileKey: str
        :return: ( the objects streaming body or None , true if successful)
        :rtype: ( StreamingBody, bool )
        """

        try:
            fileObj, flag = self.getFileObject(fileKey)
            if not flag:
                return (None, False)

            if not 'Body' in fileObj:
                logging.warning(f"Error while accessing stream object for file {fileKey}")
                return (None, False)

            if not isinstance(fileObj['Body'], StreamingBody):
                logging.warning(f"Error while accessing streaming body for file {fileKey}")
                return (None, False)

            return (fileObj['Body'], True)

        except Exception as e:
            logging.error(f"Error while accessing stream object for file {fileKey}: {str(e)}")
            return (None, False)

    #######################################################
    def copyFile(self, inPath:str, outPath:str):
        """
        Copy a file inside the same bucket

        :param inPath: The file to be copied
        :type inPath: str
        :param outPath: The new file path
        :type outPath: str
        :return: Nothing
        :rtype: None
        
        """
        source = self.bucketName+"/"+inPath # for some stupid reason, this is necessary
        out = outPath # sometimes, the folder name needs to be in front as well
        retVal = self.s3_client.copy_object(ACL='private', Bucket=self.bucketName, CopySource=source, Key=out)

    #######################################################
    def deleteFile(self, fileKey):
        """
        Delete a file from storage.

        :param fileKey: The key with which to retrieve the file again later
        :type fileKey: Str
        :return: File or error
        :rtype: BytesIO or Error
        """

        response = self.s3_client.delete_object(Bucket=self.bucketName, Key=fileKey)
        # TODO: if response...

        return True
    
    #######################################################
    def getContentOfBucket(self, prefix):
        """
        Retrieve the content of a certain bucket from the storage.

        :param prefix: The prefix of the folder
        :type prefix: str
        :return: Dictionary of files
        :rtype: Dict
        
        """
        response = self.s3_client.list_objects_v2(Bucket=self.bucketName, Prefix=prefix)
        outList = []
        for idx, elem in enumerate(response["Contents"]):
            resp = self.s3_client.head_object(Bucket=self.bucketName, Key=elem["Key"])
            elem["Metadata"] = resp["Metadata"]
            outList.append(elem)
        return outList
    
    #######################################################
    def getDownloadLinkPrefix(self):
        """
        What is the prefix for downloading files?

        :return: Link prefix
        :rtype: str
        
        """
        return self.downloadLinkPrefix

##########################################################

manageLocalS3 = ManageS3(settings.AES_ENCRYPTION_KEY,'us-east-1','files',settings.LOCALSTACK_ENDPOINT, settings.LOCALSTACK_ACCESS_KEY, settings.LOCALSTACK_SECRET, True, "")
manageRemoteS3 = ManageS3(settings.AES_ENCRYPTION_KEY,settings.AWS_LOCATION, settings.AWS_BUCKET_NAME, f"https://{settings.AWS_BUCKET_NAME}.{settings.AWS_REGION_NAME}.{settings.AWS_S3_ENDPOINT_URL}", settings.AWS_ACCESS_KEY_ID, settings.AWS_SECRET_ACCESS_KEY, False, f"https://{settings.AWS_BUCKET_NAME}.{settings.AWS_REGION_NAME}.{settings.AWS_CDN_ENDPOINT}/")
manageRemoteS3Buckets = ManageS3(settings.AES_ENCRYPTION_KEY,settings.AWS_LOCATION, settings.AWS_BUCKET_NAME, f"https://{settings.AWS_REGION_NAME}.{settings.AWS_S3_ENDPOINT_URL}", settings.AWS_ACCESS_KEY_ID, settings.AWS_SECRET_ACCESS_KEY, False, f"https://{settings.AWS_BUCKET_NAME}.{settings.AWS_REGION_NAME}.{settings.AWS_CDN_ENDPOINT}/")