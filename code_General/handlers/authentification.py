"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Authentification handling using Auth0
"""

import json, datetime, requests, logging
from urllib.parse import quote_plus, urlencode

from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse

from ..utilities import basics, rights, signals
from ..connections.postgresql import pgProfiles
from ..connections import auth0, redis
from ..definitions import SessionContent, ProfileClasses, UserDescription


logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

#######################################################
@require_http_methods(["GET"])
def isLoggedIn(request):
    """
    Check whether the token of a user has expired and a new login is necessary

    :param request: User session token
    :type request: Dictionary
    :return: True if the token is valid or False if not
    :rtype: HttpResponse
    """
    # Initialize session if not done already to generate session key
    if SessionContent.INITIALIZED not in request.session:
        request.session[SessionContent.INITIALIZED] = True

    # Check if user is already logged in
    if "user" in request.session:
        if basics.checkIfTokenValid(request.session["user"]):
            return HttpResponse("Success",status=200)
        else:
            return HttpResponse("Failed",status=200)
    
    return HttpResponse("Failed",status=200)

#######################################################
@require_http_methods(["POST"])
def setLocaleOfUser(request):
    """
    Get the preferred language of the user from the frontend

    :param request: Information from the frontend
    :type request: Dictionary-like object (nonmutable)
    :return: Success if language could be saved in session, failed if not
    :rtype: HttpResponse
    
    """
    try:
        # Initialize session if not done already to generate session key
        if SessionContent.INITIALIZED not in request.session:
            request.session[SessionContent.INITIALIZED] = True
        
        info = json.loads(request.body.decode("utf-8"))
        localeOfUser = info["locale"]
        if "-" in localeOfUser: # test supported languages here
            request.session[SessionContent.LOCALE] = localeOfUser
            pgProfiles.ProfileManagementBase.setUserLocale(request.session)
            return HttpResponse("Success",status=200)

        return HttpResponse("Failed", status=200)
    except Exception as e:
        loggerError.error(f"getLocaleOfUser: {str(e)}")
        return HttpResponse("Failed", status=500)


#######################################################
@require_http_methods(["GET"])
@basics.checkIfUserIsLoggedIn(json=True)
def provideRightsFile(request):
    """
    Returns the json file containing the rights for the frontend

    :param request: GET request
    :type request: HTTP GET
    :return: JSON Response.
    :rtype: JSONResponse

    """
    
    return JsonResponse(rights.rightsManagement.getFile(), safe=False)

#######################################################
@require_http_methods(["GET"])
def loginUser(request):
    """
    Return a link for redirection to Auth0.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP Response.
    :rtype: HTTP Link as str

    """
    # Check if Login is mocked
    mocked = False
    if "Usertype" in request.headers and (request.headers["Usertype"] == "fakeUser" or request.headers["Usertype"] == "fakeAdmin" or request.headers["Usertype"] == "fakeOrganization"):
        mocked = True

    if settings.PRODUCTION or settings.STAGING:
        mocked = False
        #return HttpResponse("Currently, logging in is not allowed. Sorry.", status=403)

    # check number of login attempts
    if mocked is False:
        if SessionContent.NUMBER_OF_LOGIN_ATTEMPTS in request.session:
            assert request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] <= 0, f"In {loginUser.__name__}: Expected non-negative number of login attempts, got {request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS]}"
            if (datetime.datetime.now() - datetime.datetime.strptime(request.session[SessionContent.LAST_LOGIN_ATTEMPT],"%Y-%m-%d %H:%M:%S.%f")).seconds > 300:
                request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] = 0
                request.session[SessionContent.LAST_LOGIN_ATTEMPT] = str(datetime.datetime.now())
            else:
                request.session[SessionContent.LAST_LOGIN_ATTEMPT] = str(datetime.datetime.now())

            if request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] > 10:
                return HttpResponse("Too many login attempts! Please wait 5 Minutes.", status=429)
            else:
                request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] += 1
        else:
            request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] = 1
            request.session[SessionContent.LAST_LOGIN_ATTEMPT] = str(datetime.datetime.now())

    # set type of user
    isPartOfOrganization = False
    if "Usertype" not in request.headers:
        request.session[SessionContent.usertype] = "user"
        request.session[SessionContent.IS_PART_OF_ORGANIZATION] = False
        request.session[SessionContent.PG_PROFILE_CLASS] = "user"
    else:
        userType = request.headers["Usertype"]
        if userType == "organization" or userType == "manufacturer" or userType == "fakeOrganization":
            request.session[SessionContent.usertype] = "organization"
            request.session[SessionContent.IS_PART_OF_ORGANIZATION] = True
            request.session[SessionContent.PG_PROFILE_CLASS] = ProfileClasses.organization
            isPartOfOrganization = True
        elif userType == "fakeAdmin" and mocked is True:
            request.session[SessionContent.usertype] = "admin"
            request.session[SessionContent.IS_PART_OF_ORGANIZATION] = False
            request.session[SessionContent.PG_PROFILE_CLASS] = ProfileClasses.user
        else:
            request.session[SessionContent.usertype] = "user"
            request.session[SessionContent.IS_PART_OF_ORGANIZATION] = False
            request.session[SessionContent.PG_PROFILE_CLASS] = ProfileClasses.user

    if "Path" not in request.headers:
        request.session[SessionContent.PATH_AFTER_LOGIN] = settings.FORWARD_URL
    else:
        request.session[SessionContent.PATH_AFTER_LOGIN] = settings.FORWARD_URL + request.headers["Path"]
        
    register = ""
    if "Register" in request.headers and mocked is False:
        if request.headers["Register"] == "true":
            register = "&screen_hint=signup"

    request.session.modified = True
    if mocked:
        request.session[SessionContent.MOCKED_LOGIN] = True
        return HttpResponse("http://127.0.0.1:8000"+reverse("callbackLogin"))
    else:
        if isPartOfOrganization:
            uri = auth0.authorizeRedirectOrga(request, reverse("callbackLogin"))
        else:
            uri = auth0.authorizeRedirect(request, reverse("callbackLogin"))
        # return uri and redirect to register if desired
        return HttpResponse(uri.url + register)

#######################################################
def setOrganizationName(request):
    """
    Set's the Organization name based on the information of the token

    :param request: request containing OAuth Token
    :type request: Dict
    :return: Nothing
    :rtype: None

    """
    if settings.AUTH0_CLAIMS_URL+"claims/organization" in request.session["user"]["userinfo"]:
        if len(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/organization"]) != 0:
            request.session[SessionContent.ORGANIZATION_NAME] = request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/organization"]
        else:
            request.session[SessionContent.ORGANIZATION_NAME] = ""
    else:
        request.session[SessionContent.ORGANIZATION_NAME] = ""

#######################################################
def retrieveRolesAndPermissionsForMemberOfOrganization(session):
    """
    Get the roles and the permissions via API from Auth0

    :param session: The session of the user
    :type session: Dict
    :return: Dict with roles and permissions
    :rtype: Dict
    """
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            'Cache-Control': "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        assert baseURL != "https://", f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: AUTH0_DOMAIN in settings not set"
        orgID = session["user"]["userinfo"]["org_id"]
        userID = pgProfiles.profileManagement[session[SessionContent.PG_PROFILE_CLASS]].getUserKey(session)

        
        response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers) )
        if isinstance(response, Exception):
            raise response
        roles = response
        
        for entry in roles:
            response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{entry["id"]}/permissions', headers=headers) )
            if isinstance(response, Exception):
                raise response
            else:
                permissions = response
        
        outDict = {"roles": roles, "permissions": permissions}
        return outDict
    except Exception as e:
        return e

#######################################################
def retrieveRolesAndPermissionsForStandardUser(session):
    """
    Get the roles and the permissions via API from Auth0

    :param session: The session of the user
    :type session: Dict
    :return: Dict with roles and permissions
    :rtype: Dict
    """
    try:
        headers = {
            'authorization': f'Bearer {auth0.apiToken.accessToken}',
            'content-Type': 'application/json',
            'Cache-Control': "no-cache"
        }
        baseURL = f"https://{settings.AUTH0_DOMAIN}"
        assert baseURL != "https://", f"In {retrieveRolesAndPermissionsForStandardUser.__name__}: AUTH0_DOMAIN in settings not set"
        userID = pgProfiles.profileManagement[session[SessionContent.PG_PROFILE_CLASS]].getUserKey(session)
        
        response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}/roles', headers=headers) )
        if isinstance(response, Exception):
            raise response
        roles = response

        # set default role
        if len(roles) == 0 and session[SessionContent.usertype] == "user":
            response = basics.handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}/roles', headers=headers, json={"roles": [auth0.auth0Config["IDs"]["standard_role"]]}))
            roles = [{"id":settings.AUTH0_DEFAULT_ROLE_ID}]
            #same as for Auth0_Domain
        
        for entry in roles:
            response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{entry["id"]}/permissions', headers=headers) )
            if isinstance(response, Exception):
                raise response
            else:
                permissions = response
        
        outDict = {"roles": roles, "permissions": permissions}
        return outDict
    except Exception as e:
        return e

#######################################################
def setRoleAndPermissionsOfUser(request):
    """
    Set's the role and the permissions of the user based on the information of the token

    :param request: request containing OAuth Token
    :type request: Dict
    :return: Exception or True
    :rtype: Exception or Bool

    """
    try:
          
        # gather roles from organization if the user is in one
        if "org_id" in request.session["user"]["userinfo"]:
            resultDict = retrieveRolesAndPermissionsForMemberOfOrganization(request.session)
            if isinstance(resultDict, Exception):
                raise resultDict
        else:
            resultDict = retrieveRolesAndPermissionsForStandardUser(request.session)
            if isinstance(resultDict, Exception):
                raise resultDict

        request.session[SessionContent.USER_ROLES] = resultDict["roles"]
        request.session[SessionContent.USER_PERMISSIONS] = {x["permission_name"]: "" for x in resultDict["permissions"] } # save only the permission names, the dict is for faster access

        # check if person is admin, global role so check works differently
        #same as for Auth0_Domain
        if settings.AUTH0_CLAIMS_URL+"claims/roles" in request.session["user"]["userinfo"]:
            if len(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]) != 0:
                if "semper-admin" in request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]:
                    request.session[SessionContent.usertype] = "admin"

        return True
    except Exception as e:
        loggerError.error(f'Generic Exception: {e}')
        return e

#######################################################
@require_http_methods(["POST", "GET"])
def callbackLogin(request):
    """
    TODO: Check if user really is part of an organization or not -> check if misclick at login, and set flags and instances here
    Get information back from Auth0.
    Add user to database if entry doesn't exist.

    :param request: POST request
    :type request: HTTP POST
    :return: URL forwarding with success to frontend/user
    :rtype: HTTP Link as redirect

    """
    try:
        # Check if mocked
        mocked = False
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            mocked = True

        # authorize callback token or write fake data
        if not mocked:
            if request.session[SessionContent.IS_PART_OF_ORGANIZATION]:
                token = auth0.authorizeTokenOrga(request)
            else:
                token = auth0.authorizeToken(request)
        else:
            request.session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "type": ""}}
            request.session["user"]["userinfo"]["sub"] = "auth0|testuser"
            request.session["user"]["userinfo"]["nickname"] = "testuser"
            request.session["user"]["userinfo"]["email"] = "testuser@test.de"
            request.session[SessionContent.USER_ROLES] = [{"id":settings.AUTH0_DEFAULT_ROLE_ID}]
            #same as for Auth0_Domain
            request.session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:messages": "","processes:edit": "","processes:delete": "","processes:files": ""}
            

        # email of user was not verified yet, tell them that!
        if not mocked and token["userinfo"]["email_verified"] == False:
            return HttpResponseRedirect(settings.FORWARD_URL+"/verifyEMail")#, status=401)
            #same as for Auth0_Domain

        # convert expiration time to the corresponding date and time
        if not mocked:
            now = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=token["expires_at"])
            request.session["user"] = token
            request.session["user"]["tokenExpiresOn"] = str(now)
        else:
            currentTime = datetime.datetime.now()
            request.session["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
        

        # get roles and permissions
        if not mocked:
            setOrganizationName(request)
            retVal = setRoleAndPermissionsOfUser(request)
            if isinstance(retVal, Exception):
                raise retVal
        elif request.session[SessionContent.IS_PART_OF_ORGANIZATION]:
                request.session[SessionContent.ORGANIZATION_NAME] = "testOrganization"
                request.session["user"]["userinfo"]["org_id"] = "id123"
                request.session[SessionContent.USER_PERMISSIONS].update({"orga:read": "", "orga:edit": "", "orga:delete": "", "resources:read": "", "resources:edit": ""})

        # Get Data from Database or create entry in it for logged in User
        orgaObj = None
        if request.session[SessionContent.IS_PART_OF_ORGANIZATION]:
            orgaObj = pgProfiles.ProfileManagementOrganization.addOrGetOrganization(request.session)
            if orgaObj == None:
                raise Exception("Organization could not be found or created!")

        userObj = pgProfiles.profileManagement[request.session[SessionContent.PG_PROFILE_CLASS]].addUserIfNotExists(request.session, orgaObj)
        if isinstance(userObj, Exception):
            raise userObj
        
        # communicate that user is logged in to other apps
        signals.signalDispatcher.userLoggedIn.send(None,request=request)

        logger.info(f"{basics.Logging.Subject.USER},{request.session['user']['userinfo']['nickname']},{basics.Logging.Predicate.FETCHED},login,{basics.Logging.Object.SELF},," + str(datetime.datetime.now()))
        return HttpResponseRedirect(request.session[SessionContent.PATH_AFTER_LOGIN])
    except Exception as e:
        returnObj = HttpResponseRedirect(request.session[SessionContent.PATH_AFTER_LOGIN])
        returnObj.write(str(e))
        return returnObj

#######################################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods("GET")
def getRolesOfUser(request):
    """
    Get Roles of User.

    :param request: GET request
    :type request: HTTP GET
    :return: List of roles
    :rtype: JSONResponse
    """
    #same as for Auth0_Domain
    if settings.AUTH0_CLAIMS_URL+"claims/roles" in request.session["user"]["userinfo"]:
        if len(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]) != 0:
            return JsonResponse(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"], safe=False)
        else:
            return JsonResponse([], safe=False, status=200)
    else:
        return JsonResponse([], safe=False, status=400)

#######################################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["GET"])
def getPermissionsOfUser(request):
    """
    Get Permissions of User.

    :param request: GET request
    :type request: HTTP GET
    :return: List of roles
    :rtype: JSONResponse
    """
    if SessionContent.USER_PERMISSIONS in request.session:
        if len(request.session[SessionContent.USER_PERMISSIONS]) != 0:
            outArray = []
            for entry in request.session[SessionContent.USER_PERMISSIONS]:
                context, permission = entry.split(":")
                outArray.append({"context": context, "permission": permission})

            return JsonResponse(outArray, safe=False)
        else:
            return JsonResponse([], safe=False, status=200)
    else:
        return JsonResponse([], safe=False, status=400)

#######################################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["GET"])
def getNewRoleAndPermissionsForUser(request):
    """
    In case the role changed, get new role and new permissions from auth0

    :param request: GET request
    :type request: HTTP GET
    :return: New Permissions for User
    :rtype: JSONResponse
    """
    retVal = setRoleAndPermissionsOfUser(request)
    if isinstance(retVal, Exception):
        return HttpResponse(retVal, status=500)
    return getPermissionsOfUser(request)    

#######################################################
@require_http_methods(["GET"])
def logoutUser(request):
    """
    Delete session for this user and log out.

    :param request: GET request
    :type request: HTTP GET
    :return: URL to be forwarded
    :rtype: HTTP URL

    """
    if not basics.manualCheckifLoggedIn(request.session):
        return HttpResponse("Not logged in!")
    mock = False
    if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
        mock = True

    # Send signal to other apps that logout is occuring
    signals.signalDispatcher.userLoggedOut.send(None,request=request)

    user = pgProfiles.profileManagement[request.session[SessionContent.PG_PROFILE_CLASS]].getUser(request.session)
    if user != {}:
        pgProfiles.ProfileManagementBase.setLoginTime(user[UserDescription.hashedID])
        logger.info(f"{basics.Logging.Subject.USER},{user['name']},{basics.Logging.Predicate.PREDICATE},logout,{basics.Logging.Object.SELF},," + str(datetime.datetime.now()))
    else:
        logger.info(f"{basics.Logging.Subject.SYSTEM},,{basics.Logging.Predicate.PREDICATE},logout,{basics.Logging.Object.USER},DELETED," + str(datetime.datetime.now()))


    # Delete saved files from redis
    redis.RedisConnection().deleteKey(request.session.session_key)

    request.session.clear()
    request.session.flush()

    # return redirect(
    #     f"https://{settings.AUTH0_DOMAIN}/v2/logout?"
    #     + urlencode(
    #         {
    #             #"returnTo": request.build_absolute_uri(reverse("index")),
    #             "returnTo": request.build_absolute_uri('http://localhost:3000/callback/logout'),
    #             "client_id": settings.AUTH0_CLIENT_ID,
    #         },
    #         quote_via=quote_plus,
    #     ),
    # )

    callbackString = request.build_absolute_uri(settings.FORWARD_URL)
    #same as for Auth0_Domain

    if not mock:
        #same as for Auth0_Domain    
        return HttpResponse(f"https://{settings.AUTH0_DOMAIN}/v2/logout?" + urlencode({"returnTo": request.build_absolute_uri(callbackString),"client_id": settings.AUTH0_CLIENT_ID,},quote_via=quote_plus,))
    else:
        return HttpResponse(callbackString)