"""
Generic Backend

Silvio Weging 2024

Contains: Logic for Admin
"""
import logging
import datetime

from ..definitions import *
from ..connections.postgresql import pgProfiles, pgEvents

from ..connections import s3

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForUpdateDetailsOfUserAsAdmin(request, content):
    try:
        assert "hashedID" in content.keys(), f"In {logicForUpdateDetailsOfUserAsAdmin.__name__}: hashedID not in request"
        userHashedID = content["hashedID"]
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert isinstance(userID, str), f"In {logicForUpdateDetailsOfUserAsAdmin.__name__}: expected userID to be of type string, instead got: {type(userID)}"
        assert userID != "", f"In {logicForUpdateDetailsOfUserAsAdmin.__name__}: non-empty userID expected"

        assert "changes" in content.keys(), f"In {logicForUpdateDetailsOfUserAsAdmin.__name__}: hashedID not in request"
        changes = content["changes"]
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
        
        flag = pgProfiles.ProfileManagementUser.updateContent(request.session, changes, userID)
        if flag is None: #updateContent returns None on success
            return (None, 200)
        else:
            if isinstance(flag, Exception):
                return (flag, 500)
            else:
                return (Exception(f"Error in {logicForUpdateDetailsOfUserAsAdmin.__name__} when trying to update UserContent: {str(flag)}"), 500)
    except Exception as e:
        loggerError.error(f"Error in {logicForUpdateDetailsOfUserAsAdmin.__name__}: {str(e)}")
        return (e, 500)

##############################################
def logicForDeleteUserAsAdmin(request, userHashedID):
    try:
        assert userHashedID != "", f"In {logicForDeleteUserAsAdmin.__name__}: userHashedID is blank"
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert userID != "", f"In {logicForDeleteUserAsAdmin.__name__}: userID is blank"
        
        # websocket event for that user
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(userHashedID[:80], {
                "type": "sendMessageJSON",
                "dict": {"eventType": "accountEvent", "context": "deleteUser"},
            })

        flag = pgProfiles.ProfileManagementUser.deleteUser(request.session, userHashedID)
        if flag is True:
            logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
            return (None, 200)
        else:
            return (Exception(f"Error in {logicForDeleteUserAsAdmin.__name__}: {str(e)}"), 500)
        
    except Exception as e:
        loggerError.error(f"Error in {logicForDeleteUserAsAdmin.__name__}: {str(e)}")
        return (e, 500)
    
##############################################
def logicForGetAllAsAdmin(request):
    try:
        users, organizations = pgProfiles.ProfileManagementBase.getAll()
        outLists = { "user" : users, "organizations": organizations }
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.FETCHED},fetched,{Logging.Object.SYSTEM}, all users and orgas," + str(datetime.datetime.now()))
        return (outLists, None, 200)
    except Exception as e:
        loggerError.error(f"Error in {logicForGetAllAsAdmin.__name__}: {str(e)}")
        return (None, e, 500)


##############################################
def logicForUpdateDetailsOfOrganizationAsAdmin(request, content):
    try:
        assert "hashedID" in content.keys(), f"In {logicForUpdateDetailsOfOrganizationAsAdmin.__name__}: hashedID not in JSON"
        orgaHashedID = content["hashedID"]
        orgaID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(orgaHashedID)
        assert "changes" in content.keys(), f"In {logicForUpdateDetailsOfOrganizationAsAdmin.__name__}: changes not in JSON"
        changes = content["changes"] 
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))

        assert orgaHashedID != "", f"In {logicForUpdateDetailsOfOrganizationAsAdmin.__name__}: orgaHashedID is blank"
        orgaID = orgaHashedID
        exception  = pgProfiles.ProfileManagementOrganization.updateContent(request.session, changes, orgaID)
        if exception is None:
            return (None, 200)
        else:
            if isinstance(exception, Exception):
                return (exception, 500)
            else:
                return (Exception(f"Error in {logicForUpdateDetailsOfOrganizationAsAdmin.__name__}: {str(e)}"), 500)

    except Exception as e:      
        loggerError.error(f"Error in {logicForUpdateDetailsOfOrganizationAsAdmin.__name__}: {str(e)}")
        return (e, 500)

##############################################
def logicForDeleteOrganizationAsAdmin(request, orgaHashedID):
    try:
        assert orgaHashedID != "", f"In {logicForDeleteOrganizationAsAdmin.__name__}: orgaHashedID is blank"
        flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaHashedID)
        if flag is True:
            logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},{orgaHashedID}," + str(datetime.datetime.now()))
            return (None, 200)
        else:
            if isinstance(flag, Exception):
                return (flag, 500)
            else:
                return (Exception(f"Error in {logicForDeleteOrganizationAsAdmin.__name__}: {str(e)}"), 500)

    except Exception as e:    
        loggerError.error(f"Error in {logicForDeleteOrganizationAsAdmin.__name__}: {str(e)}")
        return (e, 500)

