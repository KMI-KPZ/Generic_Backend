"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of admin view requests

"""

import logging


from ..handlers.organizations import SReqChangesOrga
from ..handlers.users import SReqChanges as SReqChangesUser

from ..utilities import basics
from  ..utilities.basics import ExceptionSerializerGeneric
from ..logics.adminLogics import *

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
        200: SResGetAllAsAdmin,
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
        outLists, exception, value = logicForGetAllAsAdmin(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(outLists, status=status.HTTP_200_OK)
        
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
        inSerializer = SReqUpdateDetailsOfUserAsAdmin(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {updateDetailsOfOrganizationAsAdmin.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            loggerError.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        content = inSerializer.data
        
        exception, value = logicForUpdateDetailsOfUserAsAdmin(request, content)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
    
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
        inSerializer = SReqUpdateDetailsOfOrganisationAsAdmin(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {updateDetailsOfOrganizationAsAdmin.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            loggerError.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        content = inSerializer.data

        exception, value = logicForUpdateDetailsOfOrganizationAsAdmin(request, content)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
    
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
        exception, value = logicForDeleteOrganizationAsAdmin(request, orgaHashedID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
        
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
        exception, value = logicForDeleteUserAsAdmin(request, userHashedID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response("Success", status=status.HTTP_200_OK)
        
    except (Exception) as error:
        message = f"Error in {deleteUserAsAdmin.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    