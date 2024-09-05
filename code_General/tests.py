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
    def createOrganization(self, client:Client):
        mockSession = client.session
        mockSession[SessionContent.MOCKED_LOGIN] = True
        mockSession[SessionContent.IS_PART_OF_ORGANIZATION] = True
        mockSession[SessionContent.PG_PROFILE_CLASS] = "organization"
        mockSession[SessionContent.usertype] = "organization"
        mockSession[SessionContent.PATH_AFTER_LOGIN] = "127.0.0.1:3000" # no real use but needs to be set
        mockSession.save()
        client.get("/"+paths["callbackLogin"][0])
        return mockSession

    #######################################################
    @staticmethod
    def createUser(client:Client):
        mockSession = client.session
        mockSession[SessionContent.MOCKED_LOGIN] = True
        mockSession[SessionContent.IS_PART_OF_ORGANIZATION] = False
        mockSession[SessionContent.PG_PROFILE_CLASS] = "user"
        mockSession[SessionContent.usertype] = "user"
        mockSession[SessionContent.PATH_AFTER_LOGIN] = "127.0.0.1:3000" # no real use but needs to be set
        mockSession.save()
        client.get("/"+paths["callbackLogin"][0])
        return mockSession

    # TESTS!
    #######################################################
    def test_updateUser(self):
        client =  Client()
        self.createUser(client)
        client.patch(path="/"+paths["updateDetails"][0], data={"changes": {"displayName": "testuser2TEST"}}, content_type="application/json")
        response = json.loads(client.get("/"+paths["getUser"][0]).content)
        self.assertIs(response["name"] == "testuser2TEST", True)
    
    #######################################################
    def test_deleteUser(self):
        client =  Client()
        self.createUser(client)
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
        self.createOrganization(client)
        response = client.patch(path="/"+paths["updateDetailsOfOrga"][0], data={"changes": { "supportedServices": [1] } }, content_type="application/json")
        self.assertIs(response.status_code == 200, True)

    #######################################################
    def test_deleteOrganization(self):
        client = Client()
        self.createOrganization(client)
        response = client.delete("/"+paths["deleteOrganization"][0])
        self.assertIs(response.status_code == 200, True)