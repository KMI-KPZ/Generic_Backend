"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Websocket for various stuff
"""
import logging

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import sync_to_async

from ..connections.postgresql import pgProfiles
from ..utilities import rights, signals

from ..definitions import SessionContent

logger = logging.getLogger("django_debug")

###################################################
class GeneralWebSocket(AsyncJsonWebsocketConsumer):
    ##########################
    def getSession(self):
        return self.scope["session"].load() 
     
    ##########################
    def setSession(self, key, value):
        self.scope["session"].save()
        self.scope["session"][key] = value
        self.scope["session"].save()

    ##########################
    async def connect(self):
        try:
            # check if person ist logged in or not. If not, refuse connection, if yes, allow it.
            session = await sync_to_async(self.getSession)()
            if "user" in session:
                # Then gather the user ID or organization id from the session user token and create room from that
                if SessionContent.IS_PART_OF_ORGANIZATION in session:
                    if session[SessionContent.IS_PART_OF_ORGANIZATION]:
                        # in other function send to that "group"/"channel"
                        orgaIDWOSC = await sync_to_async(pgProfiles.ProfileManagementBase.getUserKeyWOSC)(uID=session["user"]["userinfo"]["org_id"])
                        await self.channel_layer.group_add(orgaIDWOSC, self.channel_name)
                        # add rights
                        for entry in rights.rightsManagement.getRightsList():
                            await self.channel_layer.group_add(orgaIDWOSC+entry, self.channel_name)

                uID = await sync_to_async(pgProfiles.ProfileManagementBase.getUserKeyWOSC)(session=session)
                await self.channel_layer.group_add(uID, self.channel_name)
                # add rights
                for entry in rights.rightsManagement.getRightsList():
                    await self.channel_layer.group_add(uID+entry, self.channel_name)

                # Send signal to other apps that websocket has been connected
                await sync_to_async(signals.signalDispatcher.websocketConnected.send)(None,session=session)

                await self.accept()
        except Exception as e:
            logger.error(f'could not connect websocket: {str(e)}')

    ##########################
    async def disconnect(self, code):
        try:
            session = await sync_to_async(self.getSession)()
            if "user" in session:
                # Send signal to other apps that websocket has been disconnected
                await sync_to_async(signals.signalDispatcher.websocketDisconnected.send)(None,session=session)

                if SessionContent.IS_PART_OF_ORGANIZATION in session:
                    if session[SessionContent.IS_PART_OF_ORGANIZATION]:
                        orgaIDWOSC = await sync_to_async(pgProfiles.ProfileManagementBase.getUserKeyWOSC)(uID=session["user"]["userinfo"]["org_id"])
                        await self.channel_layer.group_discard(orgaIDWOSC, self.channel_name)
                        for entry in rights.rightsManagement.getRightsList():
                            await self.channel_layer.group_discard(orgaIDWOSC+entry, self.channel_name)
                uID = await sync_to_async(pgProfiles.ProfileManagementBase.getUserKeyWOSC)(session=session)
                await self.channel_layer.group_discard(uID, self.channel_name)
                for entry in rights.rightsManagement.getRightsList():
                    await self.channel_layer.group_discard(uID+entry, self.channel_name)
                raise StopConsumer("Connection closed")
        except Exception as e:
            logger.error(f'could not disconnect websocket: {str(e)}')

    
    ##########################
    async def receive(self, text_data=None, bytes_data=None):
        #if text_data == "Printability":

        await self.send(text_data="PONG")

    ##########################
    async def send(self, text_data=None, bytes_data=None, close=False):
        return await super().send(text_data, bytes_data, close)
    
    ##########################
    async def sendMessage(self, event):
        await self.send(text_data=event["text"])

    ##########################
    async def sendMessageJSON(self, event):
        await self.send_json(content=event["dict"])
