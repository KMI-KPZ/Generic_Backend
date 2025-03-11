"""
Generic Backend

Akshay NS 2024

Contains: handlers for events
"""

import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import serializers
from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema


from ..definitions import *
from ..utilities.basics import ExceptionSerializerGeneric, checkIfUserIsLoggedIn, checkIfRightsAreSufficient, checkVersion
from ..connections.postgresql import pgProfiles, pgEvents
from ..logics.eventLogics import *

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
#######################################################

#######################################################
class SReqsEventContent(serializers.Serializer):
    primaryID =  serializers.CharField(max_length=513)
    secondaryID = serializers.CharField(max_length=513,  required=False)
    reason = serializers.CharField(max_length=513, required=False)
    content = serializers.CharField(max_length=513, required=False, allow_blank=True)
    additionalInformation = serializers.DictField(allow_empty=True, required=False)
#######################################################
class SReqsOneEvent(serializers.Serializer):
    #pgEvents.EventDescription.event, pgEvents.EventDescription.userHashedID, pgEvents.EventDescription.eventID, pgEvents.EventDescription.createdWhen
    eventType = serializers.CharField(max_length=200)
    eventID = serializers.CharField(max_length=513, required=False)
    userHashedID = serializers.CharField(max_length=513, required=False)
    eventData = SReqsEventContent()
    createdWhen = serializers.CharField(max_length=200, required=False)
    triggerEvent = serializers.BooleanField()

#######################################################
@extend_schema(
    summary="Return all events related to a user",
    description=" ",
    tags=['FE - Events'],
    request=None,
    responses={
        200: serializers.ListSerializer(child=SReqsOneEvent()),
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@checkIfUserIsLoggedIn()
@api_view(["GET"])
@checkVersion(0.3)
def getAllEventsForUser(request:Request):
    """
    Return all events related to a user

    :param request: GET Request
    :type request: HTTP GET
    :return: list of events
    :rtype: Response

    """
    try:
        listOfEvents, exception, value = logicForGetAllEventsForUser(request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        outSerializer = SReqsOneEvent(data=listOfEvents, many=True)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except (Exception) as error:
        message = f"Error in {getAllEventsForUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#######################################################
@extend_schema(
    summary="Retrieve one event in particular",
    description=" ",
    tags=['FE - Events'],
    request=None,
    responses={
        200: SReqsOneEvent,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@checkIfUserIsLoggedIn()
@api_view(["GET"])
@checkVersion(0.3)
def getOneEventOfUser(request:Request, eventID:str):
    """
    Retrieve one event in particular

    :param request: GET Request
    :type request: HTTP GET
    :return: Dict
    :rtype: JSONResponse

    """
    try:
        event, exception, value = logicForGetOneEventOfUser(eventID)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        outSerializer = SReqsOneEvent(data=event)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)
    except (Exception) as error:
        message = f"Error in {getOneEventOfUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#######################################################
@extend_schema(
    summary="Create an event from the frontend",
    description=" ",
    tags=['FE - Events'],
    request=SReqsOneEvent,
    responses={
        200: SReqsOneEvent,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@checkIfUserIsLoggedIn()
@api_view(["POST"])
@checkVersion(0.3)
def createEvent(request:Request):
    """
    Create an event from the frontend

    :param request: POST Request
    :type request: HTTP POST
    :return: Nothing
    :rtype: Response

    """
    try:
        inSerializer = SReqsOneEvent(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {createEvent.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            loggerError.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        retVal, exception, value = logicForCreateEvent(validatedInput, Request)
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        outSerializer = SReqsOneEvent(data=retVal)
        if outSerializer.is_valid():
            return Response(outSerializer.data, status=status.HTTP_200_OK)
        else:
            raise Exception(outSerializer.errors)

    except (Exception) as error:
        message = f"Error in {createEvent.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

#######################################################
@extend_schema(
    summary="Deletes one event",
    description=" ",
    tags=['FE - Events'],
    request=None,
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@checkIfUserIsLoggedIn()
@api_view(["DELETE"])
@checkVersion(0.3)
def deleteOneEvent(request:Request, eventID:str):
    """
    Deletes one event

    :param request: DELETE Request
    :type request: HTTP DELETE
    :return: Success or not
    :rtype: Response

    """
    try:
        exception, value = logicForDeleteOneEvent(eventID)
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
        message = f"Error in {deleteOneEvent.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

#######################################################
@extend_schema(
    summary="Deletes all events of a user",
    description=" ",
    tags=['FE - Events'],
    request=None,
    responses={
        200: None,
        401: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
    }
)
@checkIfUserIsLoggedIn()
@api_view(["DELETE"])
@checkVersion(0.3)
def deleteAllEventsForAUser(request:Request):
    """
    Deletes all events of a user

    :param request: DELETE Request
    :type request: HTTP DELETE
    :return: Success or not
    :rtype: Response

    """
    try:
        exception, value = logicForDeleteAllEventsForAUser(request)
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
        message = f"Error in {deleteAllEventsForAUser.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)