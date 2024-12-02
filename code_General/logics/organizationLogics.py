"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for the organizations
"""
import logging, numpy

from ..connections.postgresql import pgProfiles
from ..definitions import *

from ..utilities import basics

from django.conf import settings
import types, json, enum, re, requests

from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

from ..connections import auth0
from ..utilities.basics import handleTooManyRequestsError
from ..modelFiles.organizationModel import Organization
from ..modelFiles.userModel import User

from ..utilities import crypto, signals
from ..utilities.basics import checkIfNestedKeyExists
from ..definitions import *

from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")
####################################################################################

@staticmethod
def updateContent(session, updates, orgaID=""):
    """
    Update user details and more.
    :param session: GET request session
    :type session: Dictionary
    :param updates: The orga details to update
    :type updates: differs
    :param orgaID: The orga ID who updates. If not given, the org_id will be used	
    :type orgaID: str
    :return: Worked or not
    :rtype: None | Exception

    """
    if orgaID == "":
        orgID = session["user"]["userinfo"]["org_id"]
    else:
        orgID = orgaID
    updated = timezone.now()
    try:
        existingObj = Organization.objects.get(subID=orgID)
        existingInfo = {OrganizationDescription.details: existingObj.details, OrganizationDescription.supportedServices: existingObj.supportedServices, OrganizationDescription.name: existingObj.name}
            
        mocked = False
        if SessionContent.MOCKED_LOGIN in session and session[SessionContent.MOCKED_LOGIN] is True:
            mocked = True
            
        sendSignals = {}

        for updateType in updates:
            details = updates[updateType]
            if updateType == OrganizationUpdateType.supportedServices:
                assert isinstance(details, list), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of list"
                supportedServices = []
                for supportedService in details:
                    supportedServices.append(supportedService)
                supportedServices.extend(existingInfo[OrganizationDescription.supportedServices])

                sendSignals[OrganizationDescription.supportedServices] = supportedServices
                existingInfo[OrganizationDescription.supportedServices] = supportedServices
            elif updateType == OrganizationUpdateType.services:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                existingInfo[OrganizationDescription.details][OrganizationDetails.services] = details
            elif updateType == OrganizationUpdateType.address:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                setToStandardAddress = details["standard"] # if the new address will be the standard address
                addressAlreadyExists = False
                newContentInDB = {}
                if OrganizationDetails.addresses in existingInfo[OrganizationDescription.details]: # add old content
                    newContentInDB = existingInfo[OrganizationDescription.details][OrganizationDetails.addresses]
                    for key in newContentInDB:
                        if "id" in details and details["id"] == newContentInDB[key]["id"]:
                            addressAlreadyExists = True
                        if setToStandardAddress:
                            newContentInDB[key]["standard"] = False

                if addressAlreadyExists == False:
                    # add new content
                    idForNewAddress = crypto.generateURLFriendlyRandomString()
                    details["id"] = idForNewAddress
                else:
                    # overwrite existing entry
                    idForNewAddress = details["id"]
                newContentInDB[idForNewAddress] = details
                existingInfo[OrganizationDescription.details][OrganizationDetails.addresses] = newContentInDB
            elif updateType == OrganizationUpdateType.displayName:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.name] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"display_name": details})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == OrganizationUpdateType.email:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.details][OrganizationDetails.email] = details
            elif updateType == OrganizationUpdateType.branding:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"branding": details})
                    #{
                        # "logo_url": "string",
                        # "colors": {
                        # "primary": "string",
                        # "page_background": "string"
                    # }
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
                    existingInfo[OrganizationDescription.details][OrganizationDetails.branding] = details
            elif updateType == OrganizationUpdateType.locale:
                assert isinstance(details, str) and ("de" in details or "en" in details), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str or locale string was wrong"
                existingInfo[OrganizationDescription.details][OrganizationDetails.locale] = details
                if not mocked:
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"metadata": { "language": details}})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
            elif updateType == OrganizationUpdateType.taxID:
                assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                existingInfo[OrganizationDescription.details][OrganizationDetails.taxID] = details
            elif updateType == OrganizationUpdateType.notifications:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                if ProfileClasses.organization in details:
                    for notification in details[ProfileClasses.organization]:   
                        if not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification) \
                            or not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.email) \
                            or not checkIfNestedKeyExists(existingInfo, OrganizationDescription.details, OrganizationDetails.notificationSettings, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification] = {UserNotificationTargets.email: True, UserNotificationTargets.event: True} 

                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.email):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.email] = details[ProfileClasses.organization][notification][UserNotificationTargets.email]
                        if checkIfNestedKeyExists(details, ProfileClasses.organization, notification, UserNotificationTargets.event):
                            existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][ProfileClasses.organization][notification][UserNotificationTargets.event] = details[ProfileClasses.organization][notification][UserNotificationTargets.event]
                                
            elif updateType == OrganizationUpdateType.priorities:
                assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                for key in details:
                    existingInfo[OrganizationDescription.details][OrganizationDetails.priorities][key] = details[key]
            else:
                raise Exception("updateType not defined")
                
        affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], updatedWhen=updated)
            
        if len(sendSignals) > 0:
            for key in sendSignals:
                match key:
                    case OrganizationDescription.supportedServices:
                        signals.signalDispatcher.orgaServiceDetails.send(None, orgaID=existingObj.hashedID, details=sendSignals[key])
            
        return None
    except (Exception) as error:
        logger.error(f"Error updating organization details: {str(error)}")
        return error

##############################################
@staticmethod
def deleteContent(session, updates, orgaID=""):
    """
    Delete certain orga details.

    :param session: GET request session
    :type session: Dictionary
    :param updates: The orga details to update
    :type updates: differs
    :param orgaID: The orga ID to update. If not given, the subID will be used	
    :type orgaID: str
    :return: If it worked or not
    :rtype: None | Exception

    """
    if orgaID == "":
        orgID = session["user"]["userinfo"]["org_id"]
    else:
        orgID = orgaID
    updated = timezone.now()
    try:
        existingObj = Organization.objects.get(subID=orgID)
        existingInfo = {OrganizationDescription.details: existingObj.details, OrganizationDescription.supportedServices: existingObj.supportedServices, OrganizationDescription.name: existingObj.name}
        
        sendSignals = {}
        
        for updateType in updates:
            details = updates[updateType]
            
            if updateType == OrganizationUpdateType.address:
                assert isinstance(details, str), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of str"
                del existingInfo[OrganizationDescription.details][OrganizationDetails.addresses][details]
            elif updateType == OrganizationUpdateType.supportedServices:
                assert isinstance(details, list), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of list"
                # deletion not necessary because the array is set in the changes function without the not set services
                existingInfo[OrganizationDescription.supportedServices] = [elem for elem in existingInfo[OrganizationDescription.supportedServices] if elem not in details]
                sendSignals[OrganizationDescription.supportedServices] = details
            else:
                raise Exception("updateType not defined")
        
        affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], updatedWhen=updated)
        
        for key in sendSignals:
            match key:
                case OrganizationUpdateType.supportedServices:
                    signals.signalDispatcher.orgaServiceDeletion.send(None, orgaID=existingObj.hashedID, details=sendSignals[key])
        return None
    except (Exception) as error:
        logger.error(f"Error deleting orga details: {str(error)}")
        return error

##############################################


