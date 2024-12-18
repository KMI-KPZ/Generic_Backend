"""
Part of Semper-KI software

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


##############################################
def logicForDeleteUserAsAdmin(userHashedID, request):
    assert userHashedID != "", f"In {logicForDeleteUserAsAdmin.cls.__name__}: userHashedID is blank"
    userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
    assert userID != "", f"In {logicForDeleteUserAsAdmin.cls.__name__}: userID is blank"
    
    # websocket event for that user
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(userHashedID[:80], {
            "type": "sendMessageJSON",
            "dict": {"eventType": "accountEvent", "context": "deleteUser"},
        })

    flag = pgProfiles.ProfileManagementUser.deleteUser(request.session, userHashedID)
    if flag is True:
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
    return flag
    
##############################################
def logicForGetAllAsAdmin(request):
    users, organizations = pgProfiles.ProfileManagementBase.getAll()
    outLists = { "user" : users, "organizations": organizations }
    logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.FETCHED},fetched,{Logging.Object.SYSTEM}, all users and orgas," + str(datetime.datetime.now()))
    return outLists

##############################################
def logicForDeleteOrganizationAsAdmin(orgaHashedID, request):
    assert orgaHashedID != "", f"In {logicForDeleteOrganizationAsAdmin.cls.__name__}: orgaHashedID is blank"
    orgaID = orgaHashedID

    flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
    if flag is True:
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
    return flag

##############################################

