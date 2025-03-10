"""
Part of Semper-KI software

Silvio Weging 2025

Contains: Temporary Folder utility
"""
import tempfile, logging, os

loggerError = logging.getLogger("errors")
##################################################
class TemporaryFolder():
    """
    A class to manage the temporary folder and create temporary files
    
    """
    ##################################################
    def __init__(self):
        self._temporaryFolder = tempfile.TemporaryDirectory()
        self._temporaryFolderPath = self._temporaryFolder.name

    ##################################################
    def __del__(self):
        self._temporaryFolder.cleanup()

    ##################################################
    def getTemporaryFolderPath(self) -> str:
        """
        Get the path to the temporary folder
        
        """
        return self._temporaryFolderPath
    
    ##################################################
    def createTemporaryFile(self, fileName:str, fileContent:bytes) -> str:
        """
        Create a temporary file
        
        """
        try:
            temporaryFile = open(self._temporaryFolderPath+"/"+fileName, 'wb')
            temporaryFile.write(fileContent)
            temporaryFile.close()
            return self._temporaryFolderPath+"/"+fileName
        except Exception as error:
            loggerError.error(f"Error while creating temporary file: {str(error)}")
            return ""
        
    ##################################################
    def deleteTemporaryFile(self, fileName:str) -> None:
        """
        Delete a temporary file
        
        """
        try:
            os.remove(self._temporaryFolderPath+"/"+fileName)
        except Exception as error:
            loggerError.error(f"Error while deleting temporary file: {str(error)}")

##################################################
temporaryDirectory = TemporaryFolder()
