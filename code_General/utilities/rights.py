"""
Generic Backend

Silvio Weging 2023

Contains: Service for rights management
"""

import json, copy
from django.conf import settings

#######################################################
class Rights:
    """
    Manage the rights for every path.
    """
    rightsDict = {}
    rightsList = []
    rightsFile = {}

    #######################################################
    def __init__(self):
        with open(str(settings.BASE_DIR) + "/rights.json") as rightsFile:
            tempDict = json.load(rightsFile)
            self.rightsFile = tempDict
            for entry in tempDict["Rights"]:
                permission = entry["permission"]["context"]+":"+entry["permission"]["permission"]
                self.rightsList.append(entry["permission"]["context"]+entry["permission"]["permission"])
                for elem in entry["paths"]:
                    if elem in self.rightsDict:
                        self.rightsDict[elem].add(permission)
                    else:
                        self.rightsDict[elem] = set([permission]) 

    #######################################################
    def getFile(self):
        """
        Serves the file as it is (usually for frontend)
        
        :return: File in JSON Format
        :rtype: JSON Object
        """
        outCopy = copy.deepcopy(self.rightsFile)
        for elem in outCopy["Rights"]:
            elem.pop("paths")
        return outCopy

    #######################################################
    def checkIfAllowed(self, permissions, path):
        """
        Check if permission is sufficient for that path.

        :param permissions: Permissions of that user
        :type permissions: [str]
        :param path: The name of the function (usually handlers)
        :type path: Str
        :return: True of permission sufficient, false if not.
        :rtype: Bool
        """

        for elem in self.rightsDict[path]:
            if elem in permissions:
                return True
            

        # for permission in permissions:
        #     if path in self.rightsDict[permission["permission_name"]]:
        #         return True
        
        return False
    
    #######################################################
    def checkIfAllowedWithOperation(self, permissions, path, operation):
        """
        Check if permission is sufficient for that path and operation.

        :param permissions: Permissions of that user
        :type permissions: [str]
        :param path: The name of the function (usually handlers)
        :type path: Str
        :param operation: Contains the operation (messages, files, ...) that should be checked
        :type operation: Str
        :return: True of permission sufficient, false if not.
        :rtype: Bool
        """

        for elem in self.rightsDict[path]:
            if elem in permissions and operation in elem:
                return True
        
        return False
    
    #######################################################
    def getPermissionsNeededForPath(self, path):
        """
        Return list of permissions that correspond to the given path

        :param path: path that needs to be checked
        :type path: str
        :return: list of permissions
        :rtype: list
        """

        outList = []
        for elem in self.rightsDict[path]:
            outList.append(elem.replace(':',''))
        return outList

    #######################################################
    def getRightsList(self):
        """
        Return list of permissions

        :return: List of permissions
        :rtype: list

        """

        return self.rightsList 
    
    #######################################################

rightsManagement = Rights()