"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling test calls and getting a csrf cookie
"""

import json

from django.http import HttpResponse, JsonResponse

from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

###################################################
@csrf_exempt # ONLY FOR TESTING!!!!
def testResponse(request):
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
@ensure_csrf_cookie
def testResponseCsrf(request):
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
from code_General.connections.postgresql import pgProfiles
def testCallToWebsocket(request):
    if "user" in request.session:
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(pgProfiles.ProfileManagementBase.getUserKeyWOSC(session=request.session), {
    "type": "sendMessage",
    "text": "Hello there!",
})

        return HttpResponse("Success", status=200)
    return HttpResponse("Not Logged In", status=401)

###################################################
class Counter():
    counter = 1
counter = Counter

###################################################
def dynamic(request):
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
        return JsonResponse(dynamicObject)