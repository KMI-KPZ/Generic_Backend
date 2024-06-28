"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of admin view requests

"""

import datetime, json, logging

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from Generic_Backend.code_General.modelFiles.userModel import UserDescription

from ..utilities import basics
from ..connections.postgresql import pgProfiles
from ..definitions import Logging

logger = logging.getLogger("logToFile")


# Profiles #############################################################################################################

##############################################
@basics.checkIfUserIsLoggedIn(json=True)
@basics.checkIfUserIsAdmin(json=True)
@require_http_methods(["GET"])
def getAllAsAdmin(request):
    """
    Drop all information (of the DB) about all users for admin view.

    :param request: GET request
    :type request: HTTP GET
    :return: JSON response containing all entries of users
    :rtype: JSON response

    """
    # get all information if you're an admin
    users, organizations = pgProfiles.ProfileManagementBase.getAll()
    outLists = { "user" : users, "organizations": organizations }
    logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.FETCHED},fetched,{Logging.Object.SYSTEM}, all users and orgas," + str(datetime.datetime.now()))
    return JsonResponse(outLists, safe=False)

##############################################
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@require_http_methods(["PATCH"])
def updateDetailsOfUserAsAdmin(request):
    """
    Update user details.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    content = json.loads(request.body.decode("utf-8"))
    assert "hashedID" in content.keys(), f"In {updateDetailsOfUserAsAdmin.__name__}: hashedID not in request"
    userHashedID = content["hashedID"]
    userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
    assert isinstance(userID, str), f"In {updateDetailsOfUserAsAdmin.__name__}: expected userID to be of type string, instead got: {type(userID)}"
    assert userID != "", f"In {updateDetailsOfUserAsAdmin.__name__}: non-empty userID expected"

    assert "name" in content.keys(), f"In {deleteUserAsAdmin.__name__}: name not in request"
    userName = content["name"]
    logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content, UserDescription.name, userID)
    assert isinstance(flag, bool), f"In {updateDetailsOfUserAsAdmin.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)
    
##############################################
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["PATCH"])
@basics.checkIfRightsAreSufficient()
def updateDetailsOfOrganizationAsAdmin(request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """

    content = json.loads(request.body.decode("utf-8"))["data"]["content"]
    assert "hashedID" in content.keys(), f"In {updateDetailsOfOrganizationAsAdmin.__name__}: hashedID not in request"
    orgaHashedID = content["hashedID"]
    orgaID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(orgaHashedID)
    assert "name" in content.keys(), f"In {deleteUserAsAdmin.__name__}: name not in request"
    orgaName = content["name"]
    logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content, orgaID)
    assert isinstance(flag, bool), f"In {updateDetailsOfOrganizationAsAdmin.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)

##############################################
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@require_http_methods(["DELETE"])
def deleteOrganizationAsAdmin(request):
    """
    Deletes an entry in the database corresponding to orga id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    content = json.loads(request.body.decode("utf-8"))
    assert "hashedID" in content.keys(), f"In {deleteOrganizationAsAdmin.__name__}: hashedID not in request"
    orgaID = content["hashedID"]
    assert "name" in content.keys(), f"In {deleteUserAsAdmin.__name__}: name not in request"
    orgaName = content["name"]

    flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
    assert isinstance(flag, bool), f"In {updateDetailsOfOrganizationAsAdmin.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
    if flag is True:
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)

##############################################
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@require_http_methods(["DELETE"])
def deleteUserAsAdmin(request):
    """
    Deletes an entry in the database corresponding to user id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    content = json.loads(request.body.decode("utf-8"))
    assert "hashedID" in content.keys(), f"In {deleteUserAsAdmin.__name__}: hashedID not in request"
    userHashedID = content["hashedID"]
    userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
    assert "name" in content.keys(), f"In {deleteUserAsAdmin.__name__}: name not in request"
    userName = content["name"]
    # websocket event for that user
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(pgProfiles.ProfileManagementBase.getUserKeyWOSC(uID=userID), {
            "type": "sendMessageJSON",
            "dict": {"eventType": "accountEvent", "context": "deleteUser"},
        })

    flag = pgProfiles.ProfileManagementUser.deleteUser(request.session, userHashedID)
    assert isinstance(flag, bool), f"In {deleteUserAsAdmin.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
    if flag is True:
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)
    