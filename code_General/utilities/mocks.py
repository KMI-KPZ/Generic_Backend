"""
Generic Backend

Silvio Weging 2024

Contains: Mocks for various purposes
"""

import json, logging, copy, datetime

from django.conf import settings

from ..definitions import *
from .basics import checkIfNestedKeyExists


logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
#######################################################

##################################################
# Mock account for user
def createMockUserInSession(session):
    """
    Creates everything necessary to login a mocked user on the plattform

    :param session: The session where it's saved
    :type session: Dictionary-like object
    :return: Nothing
    :rtype: None
    
    """
    currentTime = datetime.datetime.now()
    session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "type": ""}}
    session["user"]["userinfo"]["sub"] = "auth0|testuser"
    session["user"]["userinfo"]["nickname"] = "testuser"
    session["user"]["userinfo"]["email"] = "testuser@test.de"
    session["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
    # setting the user role is not necessary since permissions can be given directly!
    session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:messages": "","processes:edit": "","processes:delete": "","processes:files": ""}
    session[SessionContent.usertype] = "user" # for tests.py
    session[SessionContent.PG_PROFILE_CLASS] = "user"
    session[SessionContent.INITIALIZED] = True
    
##################################################
# Mock account for orga
def createMockOrganizationInSession(session):
    """
    Creates everything necessary to login a mocked organization on the plattform

    :param session: The session where it's saved
    :type session: Dictionary-like object
    :return: Nothing
    :rtype: None
    
    """
    currentTime = datetime.datetime.now()
    session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "org_id": ""}}
    session["user"]["userinfo"]["sub"] = "auth0|testOrga"
    session["user"]["userinfo"]["nickname"] = "testOrga"
    session["user"]["userinfo"]["email"] = "testOrga@test.de"
    session["user"]["userinfo"]["org_id"] = "id123"
    # setting the user role is not necessary since permissions can be given directly!
    session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:files": "", "processes:messages": "", "processes:edit" : "", "processes:delete": "", "orga:edit": "", "orga:delete": "", "orga:read": "", "resources:read": "", "resources:edit": ""}
    session[SessionContent.usertype] = "organization" # for tests.py
    session[SessionContent.ORGANIZATION_NAME] = "testOrga"
    session[SessionContent.INITIALIZED] = True
    session[SessionContent.PG_PROFILE_CLASS] = "organization"
    session["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))

##################################################
# Mock account for admin
def createMockAdminInSession(session):
    """
    Creates everything necessary to login a mocked admin on the plattform

    :param session: The session where it's saved
    :type session: Dictionary-like object
    :return: Nothing
    :rtype: None
    
    """
    currentTime = datetime.datetime.now()
    session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "type": ""}}
    session["user"]["userinfo"]["sub"] = "auth0|testAdmin"
    session["user"]["userinfo"]["nickname"] = "testAdmin"
    session["user"]["userinfo"]["email"] = "testAdmin@test.de"
    session["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
    session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:messages": "","processes:edit": "","processes:delete": "","processes:files": ""}
    session[SessionContent.usertype] = "admin" # for tests.py
    session[SessionContent.PG_PROFILE_CLASS] = "user"
    session[SessionContent.INITIALIZED] = True
