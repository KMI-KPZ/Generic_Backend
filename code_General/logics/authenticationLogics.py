"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for Files
"""
import logging, datetime, re
from urllib.parse import quote_plus, urlencode

from django.conf import settings
from django.urls import reverse
import requests

from ..utilities import basics, mocks, signals

from ..definitions import *
from ..connections.postgresql import pgProfiles

from ..connections import auth0, redis


from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForSetLocaleOfUser(validatedInput, request):
    try:
        assert "locale" in validatedInput.keys(), f"In {logicForSetLocaleOfUser.__name__}: locale not in request"
        localeOfUser = validatedInput["locale"]
        if "de" in localeOfUser or "en" in localeOfUser: # test supported languages here
            request.session[SessionContent.LOCALE] = localeOfUser
            if basics.manualCheckifLoggedIn(request.session):
                pgProfiles.ProfileManagementBase.setUserLocale(request.session)
                #update locale in user profile
                pgProfiles.ProfileManagementUser.updateContent(request.session, updates={"locale": localeOfUser})
            return (None, 200)
        else: 
            return (Exception("Locale not supported"), 500)
    
    except Exception as e:
        return (e, 500)

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
        assert baseURL != "https://", f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: AUTH0_DOMAIN was not added to baseURL"
        orgID = session["user"]["userinfo"]["org_id"]
        assert isinstance(orgID, str), f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: expected orgID to be of type string, instead got: {type(orgID)}"
        assert orgID != "", f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: non-empty orgID expected"
        userID = pgProfiles.profileManagement[session[SessionContent.PG_PROFILE_CLASS]].getUserKey(session)
        assert isinstance(userID, str), f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: expected userID to be of type string, instead got: {type(userID)}"
        assert userID != "", f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: non-empty userID expected"

        
        response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}/members/{userID}/roles', headers=headers) )
        if isinstance(response, Exception):
            raise response
        roles = response
        assert isinstance(roles, list), f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: expected roles to be of type list, instead got: {type(roles)}"
        
        for entry in roles:
            response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{entry["id"]}/permissions', headers=headers) )
            if isinstance(response, Exception):
                raise response
            else:
                permissions = response
                assert isinstance(permissions, list), f"In {retrieveRolesAndPermissionsForMemberOfOrganization.__name__}: expected permissions to be of type list, instead got: {type(permissions)}"
        
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
        assert baseURL != "https://", f"In {retrieveRolesAndPermissionsForStandardUser.__name__}: AUTH0_DOMAIN was not added to baseURL"
        
        userID = pgProfiles.profileManagement[session[SessionContent.PG_PROFILE_CLASS]].getUserKey(session)
        assert isinstance(userID, str), f"In {retrieveRolesAndPermissionsForStandardUser.__name__}: expected userID to be of type string, instead got: {type(userID)}"
        assert userID != "", f"In {retrieveRolesAndPermissionsForStandardUser.__name__}: non-empty userID expected"

        response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}/roles', headers=headers) )
        if isinstance(response, Exception):
            raise response
        roles = response

        # set default role
        if len(roles) == 0 and session[SessionContent.usertype] == "user":
            response = basics.handleTooManyRequestsError( lambda : requests.post(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}/roles', headers=headers, json={"roles": [auth0.auth0Config["IDs"]["standard_role"]]}))
            roles = [{"id":settings.AUTH0_DEFAULT_ROLE_ID}]
        
        for entry in roles:
            response = basics.handleTooManyRequestsError( lambda : requests.get(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["roles"]}/{entry["id"]}/permissions', headers=headers) )
            if isinstance(response, Exception):
                raise response
            else:
                permissions = response
                assert isinstance(permissions, list), f"In {retrieveRolesAndPermissionsForStandardUser.__name__}: expected permissions to be of type list, instead got: {type(permissions)}"
        
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

        assert isinstance(resultDict, dict), f"In {setRoleAndPermissionsOfUser.__name__}: expected resultDict to be of type dictionary, instead got: {type(resultDict)}"
        request.session[SessionContent.USER_ROLES] = resultDict["roles"]
        request.session[SessionContent.USER_PERMISSIONS] = {x["permission_name"]: "" for x in resultDict["permissions"] } # save only the permission names, the dict is for faster access

        # check if person is admin, global role so check works differently
        if settings.AUTH0_CLAIMS_URL+"claims/roles" in request.session["user"]["userinfo"]:
            if len(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]) != 0:
                if "semper-admin" in request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]:
                    request.session[SessionContent.usertype] = "admin"

        return True
    except Exception as e:
        loggerError.error(f'Generic Exception: {e}')
        return e

#########################################################################
def logicForLoginUser(request):
    try:
        # Check if Login is mocked
        mocked = False
        if "Usertype" in request.headers and (request.headers["Usertype"] == "fakeUser" or request.headers["Usertype"] == "fakeAdmin" or request.headers["Usertype"] == "fakeOrganization"):
            mocked = True

        if settings.PRODUCTION or settings.STAGING:
            mocked = False # this disables the possibility of h4(|<0|2Z logging in as fakeAdmin
            #return (Exception("Currently, logging in is not allowed. Sorry."), status=403)

        # check number of login attempts
        if mocked is False:
            if SessionContent.NUMBER_OF_LOGIN_ATTEMPTS in request.session:
                assert request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] >= 0, f"In {logicForLoginUser.__name__}: Expected non-negative number of login attempts, got {request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS]}"
                if (datetime.datetime.now() - datetime.datetime.strptime(request.session[SessionContent.LAST_LOGIN_ATTEMPT],"%Y-%m-%d %H:%M:%S.%f")).seconds > 300:
                    request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] = 0
                    request.session[SessionContent.LAST_LOGIN_ATTEMPT] = str(datetime.datetime.now())
                else:
                    request.session[SessionContent.LAST_LOGIN_ATTEMPT] = str(datetime.datetime.now())

                if request.session[SessionContent.NUMBER_OF_LOGIN_ATTEMPTS] > 10:
                    return (Exception("Too many login attempts! Please wait 5 Minutes."), 429)
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
        
        localization = "&ui_locales=de"
        if SessionContent.LOCALE in request.session:
            localization = f"&ui_locales={request.session[SessionContent.LOCALE].split('-')[0]}"

        request.session.modified = True
        if mocked:
            request.session[SessionContent.MOCKED_LOGIN] = True
            return ("http://127.0.0.1:8000"+reverse("callbackLogin"), 200)
        else:
            if isPartOfOrganization:
                uri = auth0.authorizeRedirectOrga(request, reverse("callbackLogin"))
            else:
                uri = auth0.authorizeRedirect(request, reverse("callbackLogin"))
            if __debug__:
                regex = "^((http|https)://)[-a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)$"
                url_regex = re.compile(regex)
                assert url_regex.match(uri.url), f"In {logicForLoginUser.__name__}: Expected uri.url to be a http or https url, instead got: {uri.url}"
            # return uri and redirect to register if desired
            return (uri.url + register + localization, 200)
    except Exception as e:
        return (e, 500)

#########################################################################
def logicForCallbackLogin(request):
    try:
        # Check if mocked
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            match request.session[SessionContent.usertype]:
                case "user":
                    mocks.createMockUserInSession(request.session)
                case "organization":
                    mocks.createMockOrganizationInSession(request.session)
                case "admin":
                    mocks.createMockAdminInSession(request.session)
        else:
            # authorize callback token 
            if request.session[SessionContent.IS_PART_OF_ORGANIZATION]:
                token = auth0.authorizeTokenOrga(request)
            else:
                token = auth0.authorizeToken(request)

            # email of user was not verified yet, tell them that!
            if token["userinfo"]["email_verified"] == False:
                return (settings.FORWARD_URL+"/verifyEMail", None, 401)#, status=401)
                #return Response(settings.FORWARD_URL+"/verifyEMail", status=status.status.HTTP_401_UNAUTHORIZED)

            # convert expiration time to the corresponding date and time
            now = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=token["expires_at"])
            request.session["user"] = token
            request.session["user"]["tokenExpiresOn"] = str(now)

            # get roles and permissions
            setOrganizationName(request)
            retVal = setRoleAndPermissionsOfUser(request)
            if isinstance(retVal, Exception):
                raise retVal
            
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
        signals.signalDispatcher.userLoggedIn.send(None,request=request._request)

        logger.info(f"{Logging.Subject.USER},{request.session['user']['userinfo']['nickname']},{Logging.Predicate.FETCHED},login,{Logging.Object.SELF},," + str(datetime.datetime.now()))
        return (request.session[SessionContent.PATH_AFTER_LOGIN], None, 200)
    except Exception as e:
        return (request.session[SessionContent.PATH_AFTER_LOGIN], e, 500)

#########################################################################
def logicForGetRolesOfUser(request):
    try:
        if settings.AUTH0_CLAIMS_URL+"claims/roles" in request.session["user"]["userinfo"]:
            if len(request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]) != 0:
                output = request.session["user"]["userinfo"][settings.AUTH0_CLAIMS_URL+"claims/roles"]
                return (output, None, 200)
            else:
                return ([], None, 200)
        else:
            return (None, Exception("Bad Request"), 400)
    except Exception as e:
        return (None, e, 500)

#########################################################################
def logicForGetPermissionsOfUser(request):
    try:
        if SessionContent.USER_PERMISSIONS in request.session:
            if len(request.session[SessionContent.USER_PERMISSIONS]) != 0:
                outArray = []
                for entry in request.session[SessionContent.USER_PERMISSIONS]:
                    context, permission = entry.split(":")
                    outArray.append({"context": context, "permission": permission})
                return (outArray, None, 200)
            else:
                return ([], None, 200)
        else:
            return ( None, Exception("Bad Request"), 400)
    except Exception as e:
        return (None, e, 500)

#########################################################################
def logicForLogoutUser(request):
    try:
        callbackString = request.build_absolute_uri(settings.FORWARD_URL)
        if not basics.manualCheckifLoggedIn(request.session):
            return (callbackString, None, 401)
    
        mock = False
        if SessionContent.MOCKED_LOGIN in request.session and request.session[SessionContent.MOCKED_LOGIN] is True:
            mock = True

        # Send signal to other apps that logout is occuring
        signals.signalDispatcher.userLoggedOut.send(None,request=request._request)

        user = pgProfiles.profileManagement[request.session[SessionContent.PG_PROFILE_CLASS]].getUser(request.session)
        assert isinstance(user, dict), f"In {logicForLogoutUser.__name__}: expected user to be of type dictionary, instead got: {type(user)}"
        if user != {}:
            pgProfiles.ProfileManagementBase.setLoginTime(user[UserDescription.hashedID])
            logger.info(f"{Logging.Subject.USER},{user['name']},{Logging.Predicate.PREDICATE},logout,{Logging.Object.SELF},," + str(datetime.datetime.now()))
        else:
            logger.info(f"{Logging.Subject.SYSTEM},,{Logging.Predicate.PREDICATE},logout,{Logging.Object.USER},DELETED," + str(datetime.datetime.now()))


        # Delete saved files from redis
        redis.RedisConnection().deleteKey(request.session.session_key)

        request.session.clear()
        request.session.flush()

        # return redirect(
        #     f"https://{settigs.AUTH0_DOMAIN}/v2/logout?"
        #     + urlencode(
        #         {
        #             #"returnTo": request.build_absolute_uri(reverse("index")),
        #             "returnTo": request.build_absolute_uri('http://localhost:3000/callback/logout'),
        #             "client_id": settings.AUTH0_CLIENT_ID,
        #         },
        #         quote_via=quote_plus,
        #     ),
        # )

        if not mock:
            return (f"https://{settings.AUTH0_DOMAIN}/v2/logout?" + urlencode({"returnTo": request.build_absolute_uri(callbackString),"client_id": settings.AUTH0_CLIENT_ID,},quote_via=quote_plus,), None, 200)
        else:
            return (callbackString, None, 200)
    except Exception as e:
        return(None, e, 500)

#########################################################################