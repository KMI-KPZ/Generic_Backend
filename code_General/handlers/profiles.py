"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Handling of database requests
"""

import datetime
import json, logging
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods

from ..utilities import basics

from ..connections.postgresql import pgProfiles

from ..definitions import SessionContent, ProfileClasses, UserDescription, OrganizationDescription

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
##############################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["POST"])
def addUserTest(request):
    """
    For testing.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP response
    :rtype: HTTP status

    """
    try:

        if request.session[SessionContent.PG_PROFILE_CLASS] == ProfileClasses.organization:
            orgaObj = pgProfiles.ProfileManagementBase.getOrganizationObject(request.session)
            returnVal = pgProfiles.ProfileManagementOrganization.addUserIfNotExists(request.session, orgaObj)
            if isinstance(returnVal, Exception):
                raise returnVal
        else:
            returnVal = pgProfiles.ProfileManagementUser.addUserIfNotExists(request.session)
            if isinstance(returnVal, Exception):
                raise returnVal

        return HttpResponse("Success")
  
    except (Exception) as exc:
        loggerError.error(f"Error creating user: {str(exc)}")
        return HttpResponse("Failed", status=500)
    
##############################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["POST"])
def addOrganizationTest(request):
    """
    For testing.

    :param request: GET request
    :type request: HTTP GET
    :return: HTTP response
    :rtype: HTTP status

    """
    try:
        returnVal = pgProfiles.ProfileManagementOrganization.addOrGetOrganization(request.session)
        if returnVal is not None:
            return HttpResponse("Success")
        else:
            return HttpResponse("Failed", status=500)
    except (Exception) as exc:
        loggerError.error(f"Error creating organization: {str(exc)}")
        return HttpResponse("Failed", status=500)

##############################################
# @checkIfUserIsLoggedIn()
# @require_http_methods(["GET"])
# def getUserTest(request):
#     """
#     Same as getUser but for testing.

#     :param request: GET request
#     :type request: HTTP GET
#     :return: User details from database
#     :rtype: JSON

#     """
#     return JsonResponse(pgProfiles.ProfileManagement.getUser(request.session))

#######################################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["GET"])
def getOrganizationDetails(request):
    """
    Return details about organization. 

    :param request: GET request
    :type request: HTTP GET
    :return: Organization details
    :rtype: Json

    """
    # Read organization details from Database
    return JsonResponse(pgProfiles.ProfileManagementBase.getOrganization(request.session))

##############################################
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["PATCH"])
@basics.checkIfRightsAreSufficient()
def updateDetailsOfOrganization(request):
    """
    Update details of organization of that user.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """

    content = json.loads(request.body.decode("utf-8"))["data"]["content"]
    logger.info(f"{basics.Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{basics.Logging.Predicate.EDITED},updated,{basics.Logging.Object.ORGANISATION},details of {pgProfiles.ProfileManagementOrganization.getOrganization(request.session)[OrganizationDescription.name]}," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementOrganization.updateContent(request.session, content)
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)

##############################################
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["DELETE"])
@basics.checkIfRightsAreSufficient()
def deleteOrganization(request):
    """
    Deletes an entry in the database corresponding to user name.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    logger.info(f"{basics.Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{basics.Logging.Predicate.DELETED},deleted,{basics.Logging.Object.ORGANISATION},organization {pgProfiles.ProfileManagementOrganization.getOrganization(request.session)[OrganizationDescription.name]}," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementBase.deleteOrganization(request.session)
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)

#######################################################
@basics.checkIfUserIsLoggedIn(json=True)
@require_http_methods(["GET"])
def getUserDetails(request):
    """
    Return details about user. 

    :param request: GET request
    :type request: HTTP GET
    :return: User details
    :rtype: Json

    """
    # Read user details from Database
    userObj = pgProfiles.ProfileManagementBase.getUser(request.session)
    userObj[SessionContent.usertype] = request.session[SessionContent.usertype]
    # show only the current organization
    if pgProfiles.ProfileManagementBase.checkIfUserIsInOrganization(request.session):
        organizationsOfUser = userObj[UserDescription.organizations].split(",")
        del userObj[UserDescription.organizations]
        currentOrganizationOfUser = pgProfiles.ProfileManagementBase.getOrganization(request.session)
        for elem in organizationsOfUser:
            if elem == currentOrganizationOfUser[OrganizationDescription.hashedID]:
                userObj["organization"] = elem
                break
    
    return JsonResponse(userObj)

##############################################
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["PATCH"])
def updateDetails(request):
    """
    Update user details.

    :param request: PATCH request
    :type request: HTTP PATCH
    :return: HTTP response
    :rtype: HTTP status

    """

    content = json.loads(request.body.decode("utf-8"))
    logger.info(f"{basics.Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{basics.Logging.Predicate.EDITED},updated,{basics.Logging.Object.SELF},details," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementUser.updateContent(request.session, content)
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)
    

##############################################
@basics.checkIfUserIsLoggedIn()
@require_http_methods(["DELETE"])
def deleteUser(request):
    """
    Deletes an entry in the database corresponding to user name.

    :param request: DELETE request
    :type request: HTTP DELETE
    :return: HTTP response
    :rtype: HTTP status

    """
    logger.info(f"{basics.Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUserName(request.session)},{basics.Logging.Predicate.DELETED},deleted,{basics.Logging.Object.SELF},," + str(datetime.datetime.now()))
    flag = pgProfiles.ProfileManagementUser.deleteUser(request.session)
    if flag is True:
        return HttpResponse("Success")
    else:
        return HttpResponse("Failed", status=500)
