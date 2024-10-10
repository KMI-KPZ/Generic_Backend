"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Decorators and functions that check if the api call is legit and such
"""
import datetime

from functools import wraps

from django.http import HttpResponse, JsonResponse

from ..modelFiles.organizationModel import OrganizationDetails
from ..modelFiles.userModel import UserDetails
from ..definitions import SessionContent
from ..connections.postgresql.pgAPIToken import checkAPITokenAndRetrieveUserObject


######### DECORATOR ##############################
def loginViaAPITokenIfAvailable():
    """
    Check whether the current user has a legit API token

    :return: Response whether the authentification token in the call was legit. If so, call the function.
    :rtype: HTTPRespone/JSONResponse, Func
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if "api/" in request.path:
                if "HTTP_AUTHORIZATION" in request.META:
                    token = request.META["HTTP_AUTHORIZATION"]
                    isOrganization, objectAssWithToken = checkAPITokenAndRetrieveUserObject(token)
                    if objectAssWithToken != None:
                        currentTime = datetime.datetime.now()
                        request.session[SessionContent.INITIALIZED] = True

                        if isOrganization:
                            request.session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "org_id": ""}}
                            request.session["user"]["userinfo"]["sub"] = objectAssWithToken.subID # TODO this could be problematic
                            request.session["user"]["userinfo"]["nickname"] = objectAssWithToken.name
                            request.session["user"]["userinfo"]["email"] = objectAssWithToken.details[OrganizationDetails.email]
                            request.session["user"]["userinfo"]["org_id"] = objectAssWithToken.subID
                            # setting the user role is not necessary since permissions can be given directly!
                            request.session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:files": "", "processes:messages": "", "processes:edit" : "", "processes:delete": "", "orga:edit": "", "orga:read": "", "resources:read": "", "resources:edit": ""}
                            request.session[SessionContent.usertype] = "organization"
                            request.session[SessionContent.ORGANIZATION_NAME] = objectAssWithToken.name
                            request.session[SessionContent.PG_PROFILE_CLASS] = "organization"
                        else:
                            request.session["user"] = {"userinfo": {"sub": "", "nickname": "", "email": "", "type": ""}}
                            request.session["user"]["userinfo"]["sub"] = objectAssWithToken.subID
                            request.session["user"]["userinfo"]["nickname"] = objectAssWithToken.name
                            request.session["user"]["userinfo"]["email"] = objectAssWithToken.details[UserDetails.email]
                            # setting the user role is not necessary since permissions can be given directly!
                            request.session[SessionContent.USER_PERMISSIONS] = {"processes:read": "", "processes:messages": "","processes:edit": "","processes:delete": "","processes:files": ""}
                            request.session[SessionContent.usertype] = "user"
                            request.session[SessionContent.PG_PROFILE_CLASS] = "user"

                        request.session["user"]["tokenExpiresOn"] = str(datetime.datetime(currentTime.year+1, currentTime.month, currentTime.day, currentTime.hour, currentTime.minute, currentTime.second, tzinfo=datetime.timezone.utc))
                        request.session.save()
                        return func(request, *args, **kwargs)
                    else:
                        return HttpResponse("API token invalid!", status=401)
                else:
                    return HttpResponse("No API token provided!", status=401)
            else:
                # no auth with token, therefore call from frontend
                return func(request, *args, **kwargs)
            
        return inner

    return decorator