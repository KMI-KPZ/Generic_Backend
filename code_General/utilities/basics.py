"""
Generic Backend

Silvio Weging 2023

Contains: Basic stuff that is imported everywhere
"""

import datetime, enum, json
from time import sleep
from functools import wraps

from django.http import HttpResponse, JsonResponse
from django.conf import settings

from rest_framework import serializers
from rest_framework import exceptions
from rest_framework.versioning import AcceptHeaderVersioning
from rest_framework.response import Response
from rest_framework import status


from ..utilities import rights
from ..utilities.customStrEnum import StrEnumExactlyAsDefined
from ..connections.redis import RedisConnection
from ..definitions import SessionContent



#######################################################
def checkIfTokenValid(token):
    """
    Check whether the token of a user has expired and a new login is necessary

    :param token: User session token
    :type token: Dictionary
    :return: True if the token is valid or False if not
    :rtype: Bool
    """
    
    if datetime.datetime.now() > datetime.datetime.strptime(token["tokenExpiresOn"],"%Y-%m-%d %H:%M:%S+00:00"):
        return False
    return True

#######################################################
def manualCheckifLoggedIn(session):
    """
    Check whether a user is logged in or not.

    :param session: Session of user
    :type session: dict
    :return: Response whether the user is logged in or not.
    :rtype: Bool
    """
    if "user" in session:
        if checkIfTokenValid(session["user"]):
            return True

    return False

#######################################################
def manualCheckifAdmin(session):
    """
    Check whether a user is an admin or not.

    :param session: Session of user
    :type session: dict
    :return: Response whether the user is an admin or not.
    :rtype: Bool
    """
    if SessionContent.usertype in session:
        if session[SessionContent.usertype] == "admin":
            return True

    return False



#################### DECORATOR ###################################
def checkIfUserIsLoggedIn(json=False):
    """
    Check whether a user is logged in or not.

    :param json: Controls if the output is in JSON Format or not
    :type json: Bool
    :return: Response whether the user is logged in or not. If so, call the function.
    :rtype: HTTPRespone/JSONResponse, Func
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if "user" in request.session:
                if checkIfTokenValid(request.session["user"]):
                    return func(request, *args, **kwargs)
                else:
                    if json:
                        return JsonResponse({}, status=401)
                    else:
                        return HttpResponse("Not logged in", status=401)
            else:
                if json:
                    return JsonResponse({}, status=401)
                else:
                    return HttpResponse("Not logged in", status=401)
            
        return inner

    return decorator

#################### DECORATOR ###################################
def checkIfUserIsAdmin(json=False):
    """
    Check whether the current user is an admin or not

    :param json: Controls if the output is in JSON Format or not
    :type json: Bool
    :return: Response whether the user is an admin or not. If so, call the function.
    :rtype: HTTPRespone/JSONResponse, Func
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if "user" in request.session:
                if request.session[SessionContent.usertype] == "admin":
                    return func(request, *args, **kwargs)
                else:
                    if json:
                        return JsonResponse({}, status=401)
                    else:
                        return HttpResponse("Not an admin!", status=401)
            else:
                if json:
                    return JsonResponse({}, status=401)
                else:
                    return HttpResponse("Not logged in", status=401)
            
        return inner

    return decorator

#######################################################
def handleTooManyRequestsError(callToAPI):
    """
    Calls the function and checks, if there were too many requests. If so, repeat the request until it's done.
    :param callToAPI: Function call to Auth0 API
    :type callToAPI: Lambda func
    :return: Either an error, or the response
    :rtype: Exception | JSON/Dict
    """
    response = callToAPI()
    iterationVariable = 0
    if response.status_code == 429:
        while response.status_code == 429:
            if iterationVariable > 100:
                return Exception("Too many requests")
            sleep(1)
            response = callToAPI()
            iterationVariable += 1
        return response.json()
    elif response.status_code != 200 and response.status_code != 201 and response.status_code != 202 and response.status_code != 203 and response.status_code != 204:
        return Exception(response.text)
    elif response.status_code == 204:
        return ""
    else:
        return response.json()

#######################################################
def manualCheckIfRightsAreSufficient(session, funcName):
    """
    Check whether a user has the permissions to do something.

    :param session: Session of user
    :type session: dict
    :param funcName: The function that called this
    :type funcName: str
    :return: Response whether the user is logged in or not.
    :rtype: Bool
    """
    if "user" in session and SessionContent.USER_PERMISSIONS in session:
        if funcName == "view":
            raise Exception("Funcname is view!")
        if session[SessionContent.usertype] == "admin" or rights.rightsManagement.checkIfAllowed(session[SessionContent.USER_PERMISSIONS], funcName):
            return True

    return False

#######################################################
def manualCheckIfRightsAreSufficientForSpecificOperation(session, funcName, operation):
    """
    Check whether a user has the permissions to do something.

    :param session: Session of user
    :type session: dict
    :param funcName: The function that called this
    :type funcName: str
    :return: Response whether the user is logged in or not.
    :rtype: Bool
    """
    if "user" in session and SessionContent.USER_PERMISSIONS in session:
        if funcName == "view":
            raise Exception("Funcname is view!")
        if session[SessionContent.usertype] == "admin" or rights.rightsManagement.checkIfAllowedWithOperation(session[SessionContent.USER_PERMISSIONS], funcName, operation):
            return True

    return False
    

#################### DECORATOR ###################################
def checkIfRightsAreSufficient(json=False):
    """
    Check whether a user has sufficient rights to call that function.

    :param json: Controls if the output is in JSON Format or not
    :type json: Bool
    :return: Response if the rights were not sufficient, function call if they were.
    :rtype: HTTPRespone/JSONResponse, Func
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            functionName = func.cls.__name__ if func.__name__ == "view" else func.__name__
            if "user" in request.session and SessionContent.USER_PERMISSIONS in request.session:
                if request.session[SessionContent.usertype] == "admin" or rights.rightsManagement.checkIfAllowed(request.session[SessionContent.USER_PERMISSIONS], functionName):
                    return func(request, *args, **kwargs)
                else:
                    if json:
                        return JsonResponse({}, status=403)
                    else:
                        return HttpResponse("Insufficient rights", status=403)
            else:
                if json:
                    return JsonResponse({}, status=403)
                else:
                    return HttpResponse("Insufficient rights", status=403)
            
        return inner

    return decorator    
        

#######################################################
# utility function to find the first occurence of an element with a condition in e.g. a list
# from: https://stackoverflow.com/questions/9542738/find-a-value-in-a-list
def findFirstOccurence(iterable, default=False, pred=None):
    """
    Returns the first true value in the iterable.

    If no true value is found, returns *default*

    If *pred* is not None, returns the first item
    for which pred(item) is true.

    :param iterable: The object (list, ...)
    :type iterable: iterable object
    :param default: The default returned, mostly None
    :type default: depends
    :param pred: A lambda function which an element of the list must fulfill
    :type pred: function
    :return: Element or default
    :rtype: depends

    """
    # first_true([a,b,c], x) --> a or b or c or x
    # first_true([a,b], x, f) --> a if f(a) else b if f(b) else x
    return next(filter(pred, iterable), default)

#######################################################
# from: https://stackoverflow.com/questions/43491287/elegant-way-to-check-if-a-nested-key-exists-in-a-dict
def checkIfNestedKeyExists(dictionary:dict, *keys) -> bool:
    """
    Check if nested keys exist in a dictionary.
    Equivalent to: if key1 in dictionary and key2 in dictionary[key1] and ...

    :param dictionary: The dictionary in question
    :type dictionary: dict
    :param keys: Key Parameters, must be in order
    :type keys: Any
    :return: True if all keys are in Dictionary
    :rtype: bool
    
    """
    if not isinstance(dictionary, dict):
        raise AttributeError(f'checkIfNestedKeyExists() expects dict as first argument.Got {type(dictionary)} {dictionary}')
    if len(keys) == 0:
        raise AttributeError('checkIfNestedKeyExists() expects at least two arguments, one given.')

    _dictionary = dictionary
    for key in keys:
        try:
            _dictionary = _dictionary[key]
        except KeyError:
            return False
    return True

#######################################################
def getNestedValue(dictionary:dict, *keys):
    """
    Check if nested keys exist in a dictionary and return the final value.
    Equivalent to: if key1 in dictionary and key2 in dictionary[key1] and ... dictionary[key1][key2]...[keyN]

    :param dictionary: The dictionary in question
    :type dictionary: dict
    :param keys: Key Parameters, must be in order
    :type keys: Any
    :return: The last value if all keys are in Dictionary, None if not
    :rtype: Any | None
    
    """
    if not isinstance(dictionary, dict):
        raise AttributeError('getNestedValue() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('getNestedValue() expects at least two arguments, one given.')

    _dictionary = dictionary
    for key in keys:
        try:
            _dictionary = _dictionary[key]
        except KeyError:
            return None
    if isinstance(_dictionary, dict):
        raise AttributeError("Not enough keys given in getNestedValue!")
    return _dictionary

#####################################################################
class ExceptionSerializerGeneric(serializers.Serializer):
    message = serializers.CharField()
    exception = serializers.CharField()

####################################################
# The following two are for version checking if that is desired.
# For this to work, the frontend has to change the accept header 
# and add "version=0.3" whereas the 0.3 is just an example
#################### DECORATOR ###################################
class VersioningForHandlers(AcceptHeaderVersioning):
    allowed_versions = ["0.3"] # default for swagger

    def __init__(self, allowedVersions) -> None:
        super().__init__()
        if str(allowedVersions) not in self.allowed_versions:
            self.allowed_versions = [str(allowedVersions)]
            
######################################################
def checkVersion(version=0.3):
    """
    Checks if the version is supported or not. If not, returns an error message.

    :param version: Version of the API to check if it is supported or not
    :type version: Float
    :return: Response whether the version is supported or not
    :rtype: HTTPRespone
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            try:
                if request.version == None:
                    #getting really tired of swaggers bullshit (of sometimes not sending the correct header)
                    return func(request, *args, **kwargs)
                versioning = VersioningForHandlers(version)
                versionOfReq = versioning.determine_version(request)
                return func(request, *args, **kwargs)
            except exceptions.NotAcceptable as e:
                return HttpResponse(f"Version mismatch! {version} required!", status=status.HTTP_406_NOT_ACCEPTABLE)
            except Exception as e:
                if func.__name__ == "view":
                    return HttpResponse(f"Exception in {func.cls.__name__}: {e}", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return HttpResponse(f"Exception in {func.__name__}: {e}", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return inner

    return decorator
