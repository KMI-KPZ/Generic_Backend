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
from ..handlers.organizations import SReqChangesOrga
from ..handlers.users import SReqChanges as SReqChangesUser

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
# serializer for getAllAsAdmin
#########################################################################
class SResGetAllAsAdmin(serializers.Serializer):   
    users = serializers.ListField(child=serializers.DictField(allow_empty=True))
    orga = serializers.ListField(child=serializers.DictField(allow_empty=True))
#########################################################################
# Handler  
@extend_schema(
    summary="Drop all information (of the DB) about all users for admin view.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: SResGetAllAsAdmin, #TODO
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn(json=True)
@basics.checkIfUserIsAdmin(json=True)
@api_view(["GET"])
@basics.checkVersion(0.3)
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
#TODO exchange serializers for Imports
#########################################################################
class SReqUpdateDetailsOfUserAsAdmin(serializers.Serializer):
    hashedID = serializers.CharField(max_length=200)   
    changes = SReqChangesUser()
#########################################################################
# Handler  
@extend_schema(
    summary="Update user details.",
    description=" ",
    request=SReqUpdateDetailsOfUserAsAdmin,
    tags=['FE - Admin'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn() 
@basics.checkIfUserIsAdmin()
@api_view(["PATCH"])
@basics.checkVersion(0.3)
def updateDetailsOfUserAsAdmin(request:Request):
    """
    Update user details.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        # TODO Body via Serializer
        #content = json.loads(request.body.decode("utf-8"))
        
        ###
        inSerializer = SReqUpdateDetailsOfUserAsAdmin(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {updateDetailsOfOrganizationAsAdmin.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        content = inSerializer.data
        ###

        assert "hashedID" in content.keys(), f"In {updateDetailsOfUserAsAdmin.cls.__name__}: hashedID not in request"
        userHashedID = content["hashedID"]
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert isinstance(userID, str), f"In {updateDetailsOfUserAsAdmin.cls.__name__}: expected userID to be of type string, instead got: {type(userID)}"
        assert userID != "", f"In {updateDetailsOfUserAsAdmin.cls.__name__}: non-empty userID expected"

        #assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        #userName = content["name"]
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.USER},{userID}," + str(datetime.datetime.now()))
        flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content, userID)
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
class SReqUpdateDetailsOfOrganisationAsAdmin(serializers.Serializer):
    hashedID = serializers.CharField(max_length=200)
    changes = SReqChangesOrga()
#########################################################################
# Handler  
@extend_schema(
    summary="Update details of organization of that user.",
    description=" ",
    request=SReqUpdateDetailsOfOrganisationAsAdmin,
    tags=['FE - Admin'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn() 
@basics.checkIfUserIsAdmin()
@api_view(["PATCH"])
@basics.checkVersion(0.3)
def updateDetailsOfOrganizationAsAdmin(request:Request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        # TODO Body via Serializer
        #content = json.loads(request.body.decode("utf-8"))["data"]["content"]
        
        ###
        inSerializer = SReqUpdateDetailsOfOrganisationAsAdmin(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {updateDetailsOfOrganizationAsAdmin.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            logger.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        content = inSerializer.data
        ###

        assert "hashedID" in content.keys(), f"In {updateDetailsOfOrganizationAsAdmin.cls.__name__}: hashedID not in request"
        orgaHashedID = content["hashedID"]
        orgaID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(orgaHashedID)
        assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        orgaName = content["name"]
        logger.info(f"{Logging.Subject.ADMIN},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.EDITED},updated,{Logging.Object.ORGANISATION},{orgaID}," + str(datetime.datetime.now()))
        flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content, orgaID)
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
# Handler  
@extend_schema(
    summary="Deletes an entry in the database corresponding to orga id.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@api_view(["DELETE"])
@basics.checkVersion(0.3)
def deleteOrganizationAsAdmin(request:Request, orgaHashedID:str):
    """
    Deletes an entry in the database corresponding to orga id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :param orgaHashedID: hashed ID of the organisation to be deleted
    :type orgaHashedID: str
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        assert orgaHashedID != "", f"In {deleteOrganizationAsAdmin.cls.__name__}: orgaHashedID is blank"
        orgaID = orgaHashedID
        #assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        #orgaName = content["name"]

        flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session, orgaID)
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
#"adminDelete": ("public/admin/deleteUser/<str:",admin.deleteUserAsAdmin)
#########################################################################
# Handler  
@extend_schema(
    summary="Deletes an entry in the database corresponding to user id.",
    description=" ",
    request=None,
    tags=['FE - Admin'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    },
)
@basics.checkIfUserIsLoggedIn()
@basics.checkIfUserIsAdmin()
@api_view(["DELETE"])
@basics.checkVersion(0.3)
def deleteUserAsAdmin(request:Request, userHashedID:str):
    """
    Deletes an entry in the database corresponding to user id.

    :param request: DELETE request
    :type request: HTTP DELETE
    :param userHashedID: hashed ID of the user to be deleted
    :type userHashedID: str
    :return: HTTP response
    :rtype: HTTP status

    """
    try:

        assert userHashedID != "", f"In {deleteUserAsAdmin.cls.__name__}: userHashedID is blank"
        userID = pgProfiles.ProfileManagementBase.getUserKeyViaHash(userHashedID)
        assert userID != "", f"In {deleteUserAsAdmin.cls.__name__}: userID is blank"
        
        #assert "name" in content.keys(), f"In {deleteUserAsAdmin.cls.__name__}: name not in request"
        #userName = content["name"]
        # websocket event for that user
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(userHashedID[:80], {
                "type": "sendMessageJSON",
                "dict": {"eventType": "accountEvent", "context": "deleteUser"},
            })

        flag = pgProfiles.ProfileManagementUser.deleteUser(request.session, userHashedID)
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
    