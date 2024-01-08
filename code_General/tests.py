"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Tests for various functions and services
"""


from django.test import TestCase, Client
from django.http import HttpRequest, HttpResponse
from django.test.client import RequestFactory
import datetime
import json, io
from .urls import paths

from .definitions import OrganizationDescription, SessionContent, UserDescription

# Create your tests here.

#######################################################
class TestProfiles(TestCase):

    # not part of the tests!
    #######################################################
    @classmethod
    def createOrganization(self, client:Client, id="", userID = ""):
        mockSession = client.session
        mockSession["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "org_id": ""}}
        mockSession["user"]["userinfo"]["sub"] = "auth0|testOrga" if userID == "" else userID
        mockSession["user"]["userinfo"]["nickname"] = "testOrga"
        mockSession["user"]["userinfo"]["email"] = "testOrga@test.de"
        mockSession["user"]["userinfo"]["org_id"] = "id123" if id == "" else id
        mockSession[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:files": "", "processes:messages": "", "processes:edit" : "", "processes:delete": "", "orga:edit": "", "orga:delete": "", "orga:read": "", "resources:read": "", "resources:edit": ""}
        mockSession[SessionContent.usertype] = "organization"
        mockSession[SessionContent.ORGANIZATION_NAME] = "testOrga"
        mockSession[SessionContent.INITIALIZED] = True
        mockSession[SessionContent.PG_PROFILE_CLASS] = "organization"
        currentTime = datetime.datetime.now()
        mockSession["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
        mockSession.save()
        client.post("/"+paths["addOrga"][0])
        client.post("/"+paths["addUser"][0])
        return mockSession

    #######################################################
    @staticmethod
    def createUser(client:Client, sub="", name=""):
        mockSession = client.session
        mockSession["user"] = {"userinfo": {"sub": "", "nickname": "", "email": ""}}
        mockSession["user"]["userinfo"]["sub"] = "auth0|testuser" if sub == "" else sub
        mockSession["user"]["userinfo"]["nickname"] = "testuser" if name == "" else name
        mockSession["user"]["userinfo"]["email"] = "testuser@test.de"
        mockSession[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:files": "", "processes:messages": "", "processes:edit" : "", "processes:delete": "", "orga:edit": "", "orga:delete": "", "orga:read": "", "resources:read": "", "resources:edit": ""}
        mockSession[SessionContent.usertype] = "user"
        mockSession[SessionContent.PG_PROFILE_CLASS] = "user"
        mockSession[SessionContent.INITIALIZED] = True
        currentTime = datetime.datetime.now()
        mockSession["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
        mockSession.save()
        client.post("/"+paths["addUser"][0])
        return mockSession

    # TESTS!
    #######################################################
    def test_updateUser(self):
        client =  Client()
        self.createUser(client)
        client.post("/"+paths["addUser"][0])
        client.patch("/"+paths["updateDetails"][0], '{"name": "testuser2TEST"}')
        response = json.loads(client.get("/"+paths["getUser"][0]).content)
        self.assertIs(response["name"] == "testuser2TEST", True)
    
    #######################################################
    def test_deleteUser(self):
        client =  Client()
        self.createUser(client, sub="auth0|deleteDude", name="deleteDude")
        client.post("/"+paths["addUser"][0])
        delResponse = client.delete("/"+paths["deleteUser"][0])
        self.assertIs(delResponse.status_code == 200, True)
    
    #######################################################
    def test_getOrganization(self):
        client = Client()
        self.createOrganization(client)
        response = json.loads(client.get("/"+paths["getOrganization"][0]).content)
        self.assertIs(response["name"] == "testOrga", True)
    
    #######################################################
    def test_updateOrganization(self):
        client = Client()
        self.createOrganization(client, "updateOrga", "auth0|updateUser")
        response = client.patch("/"+paths["updateDetailsOfOrga"][0], '{"data": {"content": { "supportedServices": [1] } } }')
        self.assertIs(response.status_code == 200, True)

    #######################################################
    def test_deleteOrganization(self):
        client = Client()
        self.createOrganization(client, "orgaDeletion", "auth0|deleteOrga")
        response = client.delete("/"+paths["deleteOrganization"][0])
        self.assertIs(response.status_code == 200, True)