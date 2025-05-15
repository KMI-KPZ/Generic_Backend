"""
Generic Backend

Silvio Weging 2024
Lukas Hein 2024

Contains: Logic for statistics
"""
import logging

from django.contrib.sessions.models import Session
from django.utils import timezone
from functools import reduce

import asyncio

from ..definitions import *

from ..utilities.basics import checkIfTokenValid

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
async def checkSession(session):
    """
    Async check if user in session is logged in or not

    :param session: coded session dict
    :type session: Dictionary
    :return: 1 or 0 if session is logged in or not
    :rtype: Integer
    """
    data = session.get_decoded() # this is slow!
    if "user" in data:
        if checkIfTokenValid(data["user"]):
            return 1
    return 0

##############################################
async def getNumOfLoggedInUsers(activeSessions):
    """
    Async check how many users are currently logged in

    :param activeSessions: sessions
    :type activeSessions: hashtable 
    :return: number of logged in users
    :rtype: Integer
    """
    
    results = await asyncio.gather(*[checkSession(session) for session in activeSessions])

    return reduce(lambda x,y: x+y, results)

##############################################
def logicForGetNumberOfUsers(request):
    try:
        activeSessions = Session.objects.filter(expire_date__gte=timezone.now())
        numOfActiveSessions = len(activeSessions)
        numOfLoggedInUsers = asyncio.run(getNumOfLoggedInUsers(activeSessions))
        output = {"active": numOfActiveSessions, "loggedIn": numOfLoggedInUsers}
        return (output, None, 200)
    except Exception as e:
        loggerError.error("Error in logicForGetNumberOfUSers: %s" % str(e))
        return (None, e, 500)