"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of requests for statistics and ip logging
"""

from django.contrib.sessions.models import Session
from django.utils import timezone
from django.conf import settings
from django.http import JsonResponse, HttpResponse
import asyncio
import time
from functools import reduce

from ..utilities.basics import checkIfTokenValid

##############################################
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
def getNumberOfUsers(request):
    """
    Return number of currently logged in users and 
    number of users that have an active session 

    :param request: GET request
    :type request: HTTP GET
    :return: json containing information
    :rtype: JSONResponse

    """
    activeSessions = Session.objects.filter(expire_date__gte=timezone.now())
    numOfActiveSessions = len(activeSessions)

    
    numOfLoggedInUsers = asyncio.run(getNumOfLoggedInUsers(activeSessions))
    
    
    output = {"active": numOfActiveSessions, "loggedIn": numOfLoggedInUsers}
    return JsonResponse(output)


##############################################
def getIpAddress(request, *args, **kwargs):
    """
    Get the IP Address of any illegit request and write it to a log file

    :param request: GET request
    :type request: HTTP GET
    :return: Response with f you
    :rtype: HTTPResponse

    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    accessTime = timezone.now()
    with open(str(settings.BASE_DIR) + "/logs/ip_log.log", 'a') as ipLogFile:
        ipLogFile.write(str(accessTime) + "\t" + request.path + "\t" + ip + "\n")
        ipLogFile.close()
    
    return HttpResponse("fu")