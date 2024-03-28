"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for aws cloud storage and file management
"""

import boto3, enum
from io import BytesIO

from ..utilities import crypto

from django.conf import settings

#####################################################################
class ManageS3():
    """
    Class for managing access to local/remote AWS

    """


    #######################################################
    def __getattr__(self, item):
        if item == "s3_client":
            self.s3_client = self.initClient()
            if self.local:
                self.createBucket(self.bucketName) # has to be done every time lest localstack forgets it exists

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

        :param endpoint: IP Adress of storage
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
        Create a named bucket to put stuff in. Should only be used freely for localstack!

        :param bucketName: Name of the bucket
        :type bucketName: Str
        :return: Success or error
        :rtype: Bool or Error
        """
        response = self.s3_client.create_bucket(ACL='private',Bucket=bucketName)
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
        file.file.seek(0) # because read() is called and has to start at the front of the file
        fileToBeUploaded = file.file
        if self.local is False:
            fileToBeUploaded = crypto.encryptAES(self.aesEncryptionKey, file.file) # encrypt file for remote AWS
        response = self.s3_client.upload_fileobj(fileToBeUploaded, self.bucketName, fileKey)
        # TODO if response...

        return True

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
        self.s3_client.download_fileobj(self.bucketName, fileKey, output)
        output.seek(0)
        if output.getbuffer().nbytes == 0: # is empty so no file has been downloaded
            return (output, False)
        if self.local is False: # remote aws files are encrypted
            decrypted_file = crypto.decryptAES(self.aesEncryptionKey, output)
            return (decrypted_file, True)
        else:
            return (output, True)
    
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