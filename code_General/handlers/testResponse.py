"""
Generic Backend

Silvio Weging 2023

Contains: Handling test calls and getting a csrf cookie
"""

import json

from django.conf import settings
from django.http import HttpResponse, JsonResponse

from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from rest_framework import status


from ..utilities.basics import ExceptionSerializerGeneric, checkIfUserIsLoggedIn 
from ..utilities.apiCalls import loginViaAPITokenIfAvailable
from drf_spectacular.utils import extend_schema

###################################################
@extend_schema(
    summary="Tests whether request and response scheme works.",
    description=" ",
    request=None,
    tags=['BE - Test'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
    },
)
@csrf_exempt # ONLY FOR TESTING!!!!
#@loginViaAPITokenIfAvailable()
@api_view(['GET'])
def testResponse(request:Request):
    """
    Tests whether request and response scheme works.

    :param request: any request
    :type request: HTTP 
    :return: Response with answer string and testheader
    :rtype: HTTP Response

    """
    outString = request.method
    response = HttpResponse(outString + " test")
    response["testHeader"] = "TESTHEADER"
    return response

###################################################
#@csrf_protect
@extend_schema(
    summary="Ensures that the csrf cookie is set correctly.",
    description=" ",
    request=None,
    tags=['BE - Test'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,  
    },
)
@ensure_csrf_cookie
@api_view(['GET'])
def testResponseCsrf(request:Request):
    """
    Ensures that the csrf cookie is set correctly.

    :param request: GET request
    :type request: HTTP GET
    :return: Response with cookie
    :rtype: HTTP Response

    """
    response = HttpResponse("CSRF worked for: " + request.method)
    return response

###################################################
from channels.generic.websocket import AsyncWebsocketConsumer
class testWebSocket(AsyncWebsocketConsumer):
    ##########################
    async def connect(self):
        await self.accept()
    ##########################
    async def disconnect(self, code):
        pass
    ##########################
    async def receive(self, text_data=None, bytes_data=None):
        print(text_data)
        await self.send(text_data="PONG")

################################################### 
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from ..connections.postgresql import pgProfiles

########################################
@extend_schema(
    summary="test call to websocket",
    description=" ",
    request=None,
    tags=['BE - Test'],
    responses={
        200: None,
        401: ExceptionSerializerGeneric,  
    },
)
@api_view(["GET"])
def testCallToWebsocket(request:Request):
    if "user" in request.session:
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(pgProfiles.ProfileManagementBase.getUserHashID(session=request.session)[:80], {
    "type": "sendMessage",
    "text": "Hello there!",
})

        return Response("Success", status=status.HTTP_200_OK)
    return Response("Not Logged In", status=status.HTTP_401_UNAUTHORIZED)

###################################################
class Counter():
    counter = 1
counter = Counter()

###################################################
@extend_schema(
    summary="Dynamically generate buttons just for fun",
    description=" ",
    request=None,
    tags=['BE - Test'],
    responses={
        200: None,
        500: ExceptionSerializerGeneric,
        
    },
)
@api_view(["GET"])
def dynamic(request:Request):
    """
    Dynamically generate buttons just for fun
    
    """
    templateEdit = {"title": "Test", "icon": "Edit", "action": "public/dynamic/", "payload": {"number": counter.counter, "Context": "Add"}}
    templateDelete = {"title": "Test", "icon": "Delete", "action": "public/dynamic/", "payload": {"number": counter.counter, "Context": "Delete"}}
    dynamicObject = {"Buttons": []}
    if request.method == "GET":
        dynamicObject["Buttons"].append(templateDelete)
        if counter.counter == 0:
            counter.counter = 1
        for i in range(counter.counter):
            dynamicObject["Buttons"].append(templateEdit)
        return JsonResponse(dynamicObject)
    else:
        content = json.loads(request.body.decode("utf-8"))
        if content["payload"]["Context"] == "Add":
            counter.counter += 1
        else:
            counter.counter -= 1
        for i in range(counter.counter):
            templateEdit["payload"]["number"] += 1
            dynamicObject["Buttons"].append(templateEdit)
        return Response(dynamicObject)
    

#######################################################
@extend_schema(
    summary=" Return Settings of django",
    description=" ",
    request=None,
    tags=['BE - Test'],
    responses={
        200: None,
    },
)
@api_view(["GET"])
def getSettingsToken(request):
    """
    Return Settings of django

    :param request: GET request
    :type request: HTTP GET
    :return: JSON with Settings
    :rtype: JSONResponse
    """
    return JsonResponse({"token": settings.BACKEND_SETTINGS})