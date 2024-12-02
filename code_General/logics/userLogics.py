"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for the users
"""
import logging, numpy

from ..connections.postgresql import pgProfiles
from ..definitions import *

from ..utilities import basics

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
####################################################################################
def logicForGetUserDetails (request):
    """
    Get the contractors for the service

    :return: The contractors
    :rtype: list
    """
    try:
        
        userObj = pgProfiles.ProfileManagementBase.getUser(request.session)
        userObj[SessionContent.usertype] = request.session[SessionContent.usertype]
        # show only the current organization
        if pgProfiles.ProfileManagementBase.checkIfUserIsInOrganization(request.session):
            organizationsOfUser = userObj[UserDescription.organizations].split(",")
            del userObj[UserDescription.organizations]
            currentOrganizationOfUser = pgProfiles.ProfileManagementBase.getOrganization(request.session)
            if isinstance(currentOrganizationOfUser, Exception):
                raise currentOrganizationOfUser
            for elem in organizationsOfUser:
                if elem == currentOrganizationOfUser[OrganizationDescription.hashedID]:
                    userObj["organization"] = elem
                    break
        else:
            del userObj[UserDescription.organizations] # users who logged in as users don't need the organization info leaked
         
        # parse addresses 
        if basics.checkIfNestedKeyExists(userObj, UserDescription.details, UserDetails.addresses):
            userObj[UserDescription.details][UserDetails.addresses] = list(userObj[UserDescription.details][UserDetails.addresses].values())
    
        
        return userObj

    except Exception as e:
        loggerError.error("Error in logicForGetUserDetails: %s" % e)
        return e
