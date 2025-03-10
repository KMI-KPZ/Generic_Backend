"""
Generic Backend

Silvio Weging 2025

Contains: Functions to create, store and retrieve preview jpgs to uploaded files
"""
import logging, os

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.conf import settings

from ..connections.s3 import manageStaticsS3
from .temporaryFolder import temporaryDirectory

loggerError = logging.getLogger("errors")
##################################################
try:
    from preview_generator.manager import PreviewManager

    ##################################################
    def createAndStorePreview(file:InMemoryUploadedFile, fileName:str, locale:str, storagePath:str) -> str|Exception:
        """
        Create a preview of a file and store it in a given path
        
        """
        try:
            outPath = ""
            temporaryFileName = temporaryDirectory.createTemporaryFile(fileName, file.read())
            file.seek(0)
            basePath = storagePath+"_preview"+".jpg"
            remotePath = "public/previews/" + basePath
            outPath = settings.STATIC_URL + "previews/" + basePath
            try:
                pathToPreviewImage = ""
                # TODO send this to another task since this can fail
                manager = PreviewManager(temporaryDirectory.getTemporaryFolderPath()+"/previews", create_folder= True)
                pathToPreviewImage = manager.get_jpeg_preview(temporaryFileName)
                if isinstance(pathToPreviewImage, Exception):
                    raise pathToPreviewImage
                f = open(pathToPreviewImage, 'rb')
                manageStaticsS3.uploadFile(remotePath, f, True)
                f.close()
                temporaryDirectory.deleteTemporaryFile(fileName)
                os.remove(pathToPreviewImage)
            except Exception as _:
                #TODO return a dummy picture
                pass
            return outPath
        except Exception as error:
            loggerError.error(f"Error while creating preview: {str(error)}")
            return error
    
    ##################################################
    def deletePreviewFile(path:str) -> None:
        """
        Deletes a preview file from the storage
        
        """
        try:
            #if path == dummy: #TODO
            #    return
            manageStaticsS3.deleteFile(path)
        except Exception as error:
            loggerError.error(f"Error while deleting preview: {str(error)}")

except ImportError:
    # implement the same functions but as dummies that don't do anything
    ##################################################
    def createAndStorePreview(file:InMemoryUploadedFile, fileName:str, locale:str, storagePath:str) -> str|Exception:
        # TODO use dummy picture
        return ""
    ##################################################
    def deletePreviewFile(path:str) -> None:
        return