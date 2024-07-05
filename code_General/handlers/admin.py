"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of admin view requests

"""

import datetime, json, logging

from django.http import HttpResponse, JsonResponse
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from Generic_Backend.code_General.modelFiles.userModel import UserDescription

from ..utilities import basics
from  ..utilities.basics import ExceptionSerializerGeneric
from ..connections.postgresql import pgProfiles
from ..definitions import Logging

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")


# Profiles #############################################################################################################

#########################################################################
# getAllAsAdmin
#"adminGetAll": ("public/admin/getAll/",admin.getAllAsAdmin)
#########################################################################
#TODO Add serializer for getAllAsAdmin
#########################################################################
# Handler  
@extend_schema(
    summary="Drop all information (of the DB) about all users for admin view.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@basics.checkIfUserIsAdmin(json=True)
@api_view(["GET"])
def getAllAsAdmin(request:Request):
    """
    Drop all information (of the DB) about all users for admin view.

    :param request: GET request
    :type request: HTTP GET
    :return: JSON response containing all entries of users
    :rtype: JSON response

    """
    try:
        # get all information if you're an admin
        users, organizations = pgProfiles.ProfileManagementBase.getAll()
        outLists = { "user" : users, "organizations": organizations }
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.FETCHED},fetched,{Logging.Object.SYSTEM}, all users and orgas," + str(datetime.datetime.now()))
        return Response(outLists)
    except Exception as error:
        message = f"Error in {getAllAsAdmin.cls.__name__} : {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# updateDetailsOfUserAsAdmin
#"adminUpdateUser": ("public/admin/updateUser/",admin.updateDetailsOfUserAsAdmin)
#########################################################################
#TODO Add serializer for updateDetailsOfUserAsAdmin
#########################################################################
# Handler  
@extend_schema(
    summary="Update user details.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@api_view(["PATCH"])
def updateDetailsOfUserAsAdmin(request:Request):
    """
    Update user details.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        content = json.loads(request.body.decode("utf-8"))
        assert "hashedID" in content.keys(), f"In {updateDetailsOfUserAsAdmin.cls.__name__}: hashedID not in request"
        userHashedID = content["hashedID"]
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert isinstance(userID, str), f"In {updateDetailsOfUserAsAdmin.cls.__name__}: expected userID to be of type string, instead got: {type(userID)}"
        assert userID != "", f"In {updateDetailsOfUserAsAdmin.cls.__name__}: non-empty userID expected"

        assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        userName = content["name"]
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
        flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content, UserDescription.name, userID)
        assert isinstance(flag, bool), f"In {updateDetailsOfUserAsAdmin.cls.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
        if flag is True:
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except (Exception) as error:
        message = f"Error in {updateDetailsOfUserAsAdmin.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#########################################################################
# updateDetailsOfOrganizationAsAdmin
#"adminUpdateOrga": ("public/admin/updateOrganization/",admin.updateDetailsOfOrganizationAsAdmin)
#########################################################################
#TODO Add serializer for updateDetailsOfOrganizationAsAdmin
#########################################################################
# Handler  
@extend_schema(
    summary="Update details of organization of that user.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@basics.checkIfUserIsLoggedIn()
@api_view(["PATCH"])
@basics.checkIfRightsAreSufficient()
def updateDetailsOfOrganizationAsAdmin(request:Request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        content = json.loads(request.body.decode("utf-8"))["data"]["content"]
        assert "hashedID" in content.keys(), f"In {updateDetailsOfOrganizationAsAdmin.cls.__name__}: hashedID not in request"
        orgaHashedID = content["hashedID"]
        orgaID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(orgaHashedID)
        assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        orgaName = content["name"]
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
        flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content, orgaID)
        assert isinstance(flag, bool), f"In {updateDetailsOfOrganizationAsAdmin.cls.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
        if flag is True:
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except (Exception) as error:
        message = f"Error in {updateDetailsOfOrganizationAsAdmin.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# deleteOrganizationAsAdmin
#"adminDeleteOrga": ("public/admin/deleteOrganization/",admin.deleteOrganizationAsAdmin)
#########################################################################
#TODO Add serializer for deleteOrganizationAsAdmin
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes an entry in the database corresponding to orga id.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@api_view(["DELETE"])
def deleteOrganizationAsAdmin(request:Request):
    """
    Deletes an entry in the database corresponding to orga id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        content = json.loads(request.body.decode("utf-8"))
        assert "hashedID" in content.keys(), f"In {deleteOrganizationAsAdmin.cls.__name__}: hashedID not in request"
        orgaID = content["hashedID"]
        assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        orgaName = content["name"]

        flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
        assert isinstance(flag, bool), f"In {updateDetailsOfOrganizationAsAdmin.cls.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
        if flag is True:
            logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except (Exception) as error:
        message = f"Error in {deleteOrganizationAsAdmin.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################################################
# deleteUserAsAdmin
#"adminDelete": ("public/admin/deleteUser/",admin.deleteUserAsAdmin)
#########################################################################
#TODO Add serializer for deleteUserAsAdmin
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes an entry in the database corresponding to user id.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@api_view(["DELETE"])
def deleteUserAsAdmin(request:Request):
    """
    Deletes an entry in the database corresponding to user id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    try:

        content = json.loads(request.body.decode("utf-8"))
        assert "hashedID" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: hashedID not in request"
        userHashedID = content["hashedID"]
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        userName = content["name"]
        # websocket event for that user
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(pgProfiles.ProfileManagementBase.getUserKeyWOSC(uID=userID), {
                "type": "sendMessageJSON",
                "dict": {"eventType": "accountEvent", "context": "deleteUser"},
            })

        flag = pgProfiles.ProfileManagementUser.deleteUser(request.session, userHashedID)
        assert isinstance(flag, bool), f"In {deleteUserAsAdmin.cls.__name__}: expected flag to be of type bool, instead got: {type(flag)}"
        if flag is True:
            logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.DELETED},deleted,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
            return Response("Success", status=status.HTTP_200_OK)
        else:
            return Response("Failed", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except (Exception) as error:
        message = f"Error in {deleteUserAsAdmin.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    