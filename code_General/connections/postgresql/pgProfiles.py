"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for database calls to manage a user/organization profile
"""
from django.conf import settings
import types, json, enum, re, requests

from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

from Generic_Backend.code_General.connections import auth0
from Generic_Backend.code_General.utilities.basics import handleTooManyRequestsError
from ...modelFiles.organizationModel import Organization
from ...modelFiles.userModel import User
from ...utilities import crypto
from ...utilities.basics import checkIfNestedKeyExists
from ...definitions import *

from logging import getLogger
logger = getLogger("errors")

#TODO: switch to async versions at some point

####################################################################################
# Profile
class ProfileManagementBase():
    ##############################################
    @staticmethod
    def getUser(session):
        """
        Check whether a user exists or not and retrieve entry.

        :param session: session
        :type session: Dictionary
        :return: User details from database
        :rtype: Dictionary

        """
        userID = session["user"]["userinfo"]["sub"]
        obj = {}
        try:
            obj = User.objects.get(subID=userID).toDict()
                
        except (Exception) as error:
            logger.error(f"Error getting user: {str(error)}")

        return obj
 
        
    ##############################################
    @staticmethod
    def getUserName(session):
        """
        Check whether a user exists or not and retrieve entry.

        :param session: session
        :type session: Dictionary
        :return: User Name from database
        :rtype: Str

        """
        if "user" in session and "userinfo" in session["user"]:
            userID = session["user"]["userinfo"]["sub"]
            try:
                name = User.objects.get(subID=userID).name
                return name
            except (Exception) as error:
                logger.error(f"Error getting user: {str(error)}")
        return str(GlobalDefaults.anonymous)
    
    ##############################################
    @staticmethod
    def getOrganization(session = {}, hashedID:str=""):
        """
        Check whether an organization exists or not and retrieve information.

        :param session: session
        :type session: Dictionary
        :param hashedID: The hash ID can be used instead
        :type hashedID: str
        :return: Organization details from database
        :rtype: Dictionary

        """
        if session != {}:
            orgaID = session["user"]["userinfo"]["org_id"]
            obj = {}
            try:
                obj = Organization.objects.get(subID=orgaID).toDict()
            except (Exception) as error:
                logger.error(f"Error getting organization: {str(error)}")

            return obj
        if hashedID != "":
            obj = {}
            try:
                obj = Organization.objects.get(hashedID=hashedID).toDict()
            except (Exception) as error:
                logger.error(f"Error getting organization: {str(error)}")

            return obj
        logger.error(f"Error getting organization because no parameter was given!")
        return {}
    
    ##############################################
    @staticmethod
    def getOrganizationObject(session):
        """
        Check whether an organization exists or not and retrieve the object.

        :param session: session
        :type session: Dictionary
        :return: Organization object
        :rtype: Database object

        """
        orgaID = session["user"]["userinfo"]["org_id"]
        obj = {}
        try:
            obj = Organization.objects.get(subID=orgaID)
        except (Exception) as error:
            logger.error(f"Error getting organization object: {str(error)}")

        return obj

    ##############################################
    @staticmethod
    def getUserHashID(session):
        """
        Retrieve hashed User ID from Session

        :param session: session
        :type session: Dictionary
        :return: Hashed user key from database
        :rtype: Str

        """
        hashID = ""
        try:
            userID = session["user"]["userinfo"]["sub"]
            userObj = User.objects.get(subID=userID)
            if userObj != None:
                hashID = userObj.hashedID
        except (Exception) as error:
            logger.error(f"Error getting user hash: {str(error)}")

        return hashID
    
    ##############################################
    @staticmethod
    def getOrganizationHashID(session):
        """
        Retrieve Organization object via hashID

        :param session: session
        :type session: Str
        :return: Hashed ID of the organization
        :rtype: Str

        """
        hashedID = ""
        orgaID = session["user"]["userinfo"]["org_id"]
        try:
            hashedID = Organization.objects.get(subID=orgaID).hashedID
        except (Exception) as error:
            logger.error(f"Error getting orga hash: {str(error)}")

        return hashedID
    
    ##############################################
    @staticmethod
    def getOrganizationName(hashedID:str):
        """
        Retrieve Organization name via hashID

        :param hashedID: ID of the organization
        :type hashedID: Str
        :return: Name of the organization
        :rtype: Str

        """
        orgaName = ""
        try:
            orgaName = Organization.objects.get(hashedID=hashedID).name
        except (Exception) as error:
            logger.error(f"Error getting orga name: {str(error)}")

        return orgaName

    ##############################################
    @staticmethod
    def getOrganizationID(session):
        """
        Retrieve Organization ID

        :param session: session
        :type session: Str
        :return: ID of the organization
        :rtype: Str

        """
        orgaID = session["user"]["userinfo"]["org_id"]
        return orgaID
    
    ##############################################
    @staticmethod
    def getUserKeyViaHash(hashedID):
        """
        Retrieve User/Orga ID via hash ID

        :param hashedID: hashed ID
        :type hashedID: str
        :return: Orga or User key from database
        :rtype: Str

        """
        IDOfUserOrOrga = ""
        try:
            IDOfUserOrOrga = Organization.objects.get(hashedID=hashedID).subID
        except (ObjectDoesNotExist) as error:
            IDOfUserOrOrga = User.objects.get(hashedID=hashedID).subID
        except (Exception) as error:
            logger.error(f"Error getting user key via hash: {str(error)}")

        return IDOfUserOrOrga
    
    ##############################################
    @staticmethod
    def getUserViaHash(hashedID):
        """
        Retrieve User/Orga Object via Database and hashkey

        :param hashedID: hashed ID
        :type hashedID: str
        :return: Object from database and whether it's an orga(True) or not
        :rtype: Tuple of Object and bool

        """
        ObjOfUserOrOrga = None
        organizationOrNot = True
        try:
            ObjOfUserOrOrga = Organization.objects.get(hashedID=hashedID)
        except (ObjectDoesNotExist) as error:
            ObjOfUserOrOrga = User.objects.get(hashedID=hashedID)
            organizationOrNot = False
        except (Exception) as error:
            logger.error(f"Error getting user via hash: {str(error)}")

        return (ObjOfUserOrOrga, organizationOrNot)
    
    ##############################################
    @staticmethod
    def getUserNameViaHash(hashedID):
        """
        Retrieve User Object via Database and hashkey

        :param hashedID: hashed ID
        :type hashedID: str
        :return: Name of user/orga from database
        :rtype: Str

        """
        ObjOfUserOrOrga = ""
        try:
            if hashedID == "SYSTEM":
                return "SYSTEM"
            ObjOfUserOrOrga = Organization.objects.get(hashedID=hashedID)
        except (ObjectDoesNotExist) as error:
            ObjOfUserOrOrga = User.objects.get(hashedID=hashedID)
        except (Exception) as error:
            logger.error(f"Error getting user via hash: {str(error)}")

        return ObjOfUserOrOrga.name

    ##############################################
    @staticmethod
    def getUserKey(session):
        """
        Retrieve User ID from Session

        :param session: session
        :type session: Dictionary
        :return: User key from database
        :rtype: Str

        """
        userID = ""
        try:
            userID = session["user"]["userinfo"]["sub"]
        except (Exception) as error:
            logger.error(f"Error getting user key: {str(error)}")

        return userID
    
    ##############################################
    @staticmethod
    def getUserOrgaKey(session):
        """
        Retrieve User ID from Session

        :param session: session
        :type session: Dictionary
        :return: User key from database
        :rtype: Str

        """
        orgaID = ""
        try:
            if "org_id" in session["user"]["userinfo"]:
                orgaID = session["user"]["userinfo"]["org_id"]
        except (Exception) as error:
            logger.error(f"Error getting user key: {str(error)}")

        return orgaID

    ##############################################
    @staticmethod
    def getUserKeyWOSC(session=None, uID=None):
        """
        Retrieve User ID from Session without special characters

        :param session: session
        :type session: Dictionary
        :return: User key from database without stuff like | or ^
        :rtype: Str

        """
        userID = ""
        try:
            if session is not None:
                userID = session["user"]["userinfo"]["sub"]
            if uID is not None:
                userID = uID
            userID = re.sub(r"[^a-zA-Z0-9]", "", userID)
        except (Exception) as error:
            logger.error(f"Error getting user key WOSC: {str(error)}")

        return userID
    
    ##############################################
    @staticmethod
    def setLoginTime(userIDHash):
        """
        Sets the last login Time to now. Used for 'Last Login'.

        :param userIDHash: userID
        :type userIDHash: str
        :return: Nothing
        :rtype: None

        """
        currUser = User.objects.get(hashedID=userIDHash)
        currUser.lastSeen = timezone.now()
        currUser.save()

    ##############################################
    @staticmethod
    def setUserLocale(session):
        """
        Sets the locale of the user in the profile.

        :param session: session
        :type session: Dictionary-like object
        :return: Nothing
        :rtype: None
        
        """
        try:
            if "user" in session:
                userID = session["user"]["userinfo"]["sub"]
                userObj = User.objects.get(subID=userID)
                if userObj != None:
                    userObj.details[UserDetails.locale] = session[SessionContent.LOCALE]
                userObj.save()
        except (Exception) as error:
            logger.error(f"Error setting user locale: {str(error)}")

    ##############################################
    @staticmethod
    def getUserLocale(session=None, hashedID=""):
        """
        Gets the locale of the user from the profile or session.

        :param session: session
        :type session: Dictionary-like object
        :param hashedID: The hashed ID of the user/orga
        :type hashedID: str
        :return: Locale
        :rtype: Str
        
        """
        try:
            if session != None:
                if "user" in session:
                    userID = session["user"]["userinfo"]["sub"]
                    userObj = User.objects.get(subID=userID)
                    if userObj != None and UserDetails.locale in userObj.details:
                        return userObj.details[UserDetails.locale]
                    else:
                        return "de-DE"
                elif SessionContent.LOCALE in session:
                    return session[SessionContent.LOCALE]
                else:
                    return "de-DE"
            elif hashedID != "":
                if ProfileManagementBase.checkIfHashIDBelongsToOrganization(hashedID):
                    orgaObj = Organization.objects.get(hashedID=hashedID)
                    if orgaObj != None and OrganizationDetails.locale in orgaObj.details:
                        return orgaObj.details[OrganizationDetails.locale]
                    else:
                        return "de-DE"
                else:
                    userObj = User.objects.get(subID=userID)
                    if userObj != None and UserDetails.locale in userObj.details:
                        return userObj.details[UserDetails.locale]
                    else:
                        return "de-DE"
            else:
                return "de-DE"
        except (Exception) as error:
            return "de-DE"



    ##############################################
    @staticmethod
    def deleteUser(session, uHashedID=""):
        """
        Delete User.

        :param session: GET request session
        :type session: Dictionary
        :return: flag if it worked or not
        :rtype: Bool

        """
        try:
            if uHashedID != "":
                affected = User.objects.filter(hashedID=uHashedID).delete()
            else:
                affected = User.objects.filter(subID=session["user"]["userinfo"]["sub"]).delete()
        except (Exception) as error:
            logger.error(f"Error deleting user: {str(error)}")
            return False
        return True
    
    ##############################################
    @staticmethod
    def deleteOrganization(session, orgID=""):
        """
        Delete Organization.

        :param session: GET request session
        :type session: Dictionary
        :return: flag if it worked or not
        :rtype: Bool

        """
        try:
            if orgID != "":
                affected = Organization.objects.filter(hashedID=orgID).delete()
            else:
                affected = Organization.objects.filter(subID=session["user"]["userinfo"]["org_id"]).delete()
            
        except (Exception) as error:
            logger.error(f"Error deleting organization: {str(error)}")
            return False
        return True
    
    ##############################################
    @staticmethod
    def getAll():
        """
        Get all Users and Organizations.

        :return: Two arrays containing all entries
        :rtype: List, List

        """
        userList = []
        orgaList = []
        for user in User.objects.all():
            userAsDict = user.toDict()
            userAsDict["organizationNames"] = ""
            for orga in user.organizations.all():
                orgaName = ProfileManagementBase.getOrganizationName(orga.hashedID)
                userAsDict["organizationNames"] += orgaName + ","
            userAsDict["organizationNames"] = userAsDict["organizationNames"].rstrip(',')
            userList.append(userAsDict)
        for orga in Organization.objects.all():
            orgaList.append(orga.toDict())
        return userList, orgaList
    
    ##############################################
    @staticmethod
    def checkIfUserIsInOrganization(session=None, hashID=""):
        """
        Check if a user is in an organization or not. Can be used to decide if additional code specific for orgas should be run

        :param session: Session
        :type session: Dictionary-like object
        :param hashID: The user ID
        :type hashID: str
        :return: True if User is in organization, False if not
        :rtype: bool
        
        """
        try:
            if session != None:
                if "user" in session and "org_id" in session["user"]["userinfo"]:
                    return True
            elif hashID != "":
                # search user and see if is in at least one orga
                userObj = User.objects.get(hashedID=hashID)
                if len(userObj.organizations.all()) > 0:
                    return True

            return False
        except Exception as error:
            logger.error(f"Error checkIfUserIsInOrganization: {str(error)}")
            return False
        
    ##############################################
    @staticmethod
    def checkIfHashIDBelongsToOrganization(hashID):
        """
        Checks if the ID belongs to an organization or not

        :param hashID: The ID in question
        :type hashID: str
        :return: True, if ID belongs to orga, False if not
        :rtype: Bool
        
        """
        try:
            Organization.objects.get(hashedID=hashID)
            return True
        except (ObjectDoesNotExist) as error:
            return False
        except Exception as error:
            logger.error(f"Error checking whether ID belongs to orga: {str(error)}")


####################################################################################
class ProfileManagementUser(ProfileManagementBase):

    ##############################################
    @staticmethod
    def addUserIfNotExists(session, organization=None):
        """
        Add user if the entry doesn't already exists.

        :param session: POST request session
        :type session: Dictionary
        :param organization: Dummy object to comply to interface of function with same name from sister class
        :type organization: None
        :return: Information about the user. Necessary to check if database entry is equal to callback information
        :rtype: User Object

        """

        userID = session["user"]["userinfo"]["sub"]
        try:
            # first get, then create
            result = User.objects.get(subID=userID)
            if UserDetails.statistics not in result.details:
                result.details[UserDetails.statistics] = {}
                result.details[UserDetails.statistics][StatisticsForProfiles.numberOfLoginsTotal] = 0
            result.details[UserDetails.statistics][StatisticsForProfiles.lastLogin] = str(timezone.now())
            result.details[UserDetails.statistics][StatisticsForProfiles.numberOfLoginsTotal] += 1
            result.save()
            return result

        except (ObjectDoesNotExist) as error:
            try:
                userName = session["user"]["userinfo"]["nickname"]
                userEmail = session["user"]["userinfo"]["email"]
                userLocale = session[SessionContent.LOCALE] if SessionContent.LOCALE in session else "de-DE"
                details = {UserDetails.email: userEmail, UserDetails.statistics: {StatisticsForProfiles.lastLogin: str(timezone.now()), StatisticsForProfiles.numberOfLoginsTotal: 1, StatisticsForProfiles.locationOfLastLogin: ""}, UserDetails.addresses: {}, UserDetails.notificationSettings: {}, UserDetails.locale: userLocale}
                updated = timezone.now()
                lastSeen = timezone.now()
                idHash = crypto.generateSecureID(userID)
                 
                createdUser = User.objects.create(subID=userID, hashedID=idHash, name=userName, details=details, updatedWhen=updated, lastSeen=lastSeen)

                return createdUser
            except (Exception) as error:
                logger.error(f"Error adding user : {str(error)}")
                return error
        except (Exception) as error:
                logger.error(f"Error adding user : {str(error)}")
                return error

    ##############################################
    @staticmethod
    def updateContent(session, updates, userID=""):
        """
        Update user details.

        :param session: GET request session
        :type session: Dictionary
        :param updates: The user details to update
        :type updates: differs
        :param userID: The user ID who updates. If not given, the subID will be used	
        :type userID: str
        :return: If it worked or not
        :rtype: None | Exception

        """
        if userID == "":
            subID = session["user"]["userinfo"]["sub"]
        else:
            subID = userID
        updated = timezone.now()
        try:
            existingObj = User.objects.get(subID=subID)
            existingInfo = {UserDescription.name: existingObj.name, UserDescription.details: existingObj.details}
            for updateType in updates:
                details = updates[updateType]
                if updateType == UserUpdateType.displayName:
                    assert isinstance(details, str), f"updateUser failed because the wrong type for details was given: {type(details)} instead of str"
                    existingInfo[UserDescription.name] = details
                elif updateType == UserUpdateType.email:
                    assert isinstance(details, str), f"updateUser failed because the wrong type for details was given: {type(details)} instead of str"
                    existingInfo[UserDescription.details][UserDetails.email] = details
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Accept": "application/json",
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"email": details})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["users"]}/{userID}', data=payload, headers=headers) )
                    if isinstance(response, Exception):
                        raise response
                elif updateType == UserUpdateType.address:
                    assert isinstance(details, dict), f"updateUser failed because the wrong type for details was given: {type(details)} instead of dict"
                    setToStandardAddress = details["standard"] # if the new address will be the standard address
                    addressAlreadyExists = False
                    newContentInDB = {}
                    if UserDetails.addresses in existingInfo[UserDescription.details]: # add old content
                        newContentInDB = existingInfo[UserDescription.details][UserDetails.addresses] 
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
                    existingInfo[UserDescription.details][UserDetails.addresses] = newContentInDB
                elif updateType == UserUpdateType.locale:
                    assert isinstance(details, str) and "-" in details, f"updateUser failed because the wrong type for details was given: {type(details)} instead of str or locale string was wrong"
                    existingInfo[UserDescription.details][UserDetails.locale] = details
                elif updateType == UserUpdateType.notifications:
                    assert isinstance(details, dict), f"updateUser failed because the wrong type for details was given: {type(details)} instead of dict"
                    for notification in details:    
                        email = False
                        event = True    
                        if checkIfNestedKeyExists(details, notification, NotificationTargets.event):
                            email = details[notification][NotificationTargets.event]
                        if checkIfNestedKeyExists(details, notification, NotificationTargets.email):
                            event = details[notification][NotificationTargets.email]
                        existingInfo[UserDescription.details][UserDetails.notificationSettings][notification] = {NotificationTargets.email: email, NotificationTargets.event: event} 
                else:
                    raise Exception("updateType not defined")
            
            affected = User.objects.filter(subID=subID).update(details=existingInfo[UserDescription.details], name=existingInfo[UserDescription.name], updatedWhen=updated)
            return None
        except (Exception) as error:
            logger.error(f"Error updating user details: {str(error)}")
            return error
        
    ##############################################
    @staticmethod
    def deleteContent(session, updates, userID=""):
        """
        Delete certain user details.

        :param session: GET request session
        :type session: Dictionary
        :param updates: The user details to update
        :type updates: differs
        :param userID: The user ID to update. If not given, the subID will be used	
        :type userID: str
        :return: If it worked or not
        :rtype: None | Exception

        """
        if userID == "":
            subID = session["user"]["userinfo"]["sub"]
        else:
            subID = userID
        updated = timezone.now()
        try:
            existingObj = User.objects.get(subID=subID)
            existingInfo = {UserDescription.name: existingObj.name, UserDescription.details: existingObj.details}
            for updateType in updates:
                details = updates[updateType]
                
                if updateType == UserUpdateType.address:
                    assert isinstance(details, str), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of str"
                    del existingInfo[UserDescription.details][UserDetails.addresses][details]
                else:
                    raise Exception("updateType not defined")
            
            affected = User.objects.filter(subID=subID).update(details=existingInfo[UserDescription.details], name=existingInfo[UserDescription.name], updatedWhen=updated)
            return None
        except (Exception) as error:
            logger.error(f"Error updating user details: {str(error)}")
            return error
    
    ##############################################
    @staticmethod
    def getClientID(session):
        """
        Get ID of current client (can be organization or user)

        :param session: request session
        :type session: dict
        :return: hashed ID
        :rtype: String

        """
        return ProfileManagementUser.getUserHashID(session)
    
    ##############################################
    @staticmethod
    def getEMailAddress(clientID:str) -> str | None:
        """
        Get Mail address of user if available

        :param clientID: The hashed ID of the user
        :type clientID: str
        :return: E-Mail address or None
        :rtype: str | None
        """
        try:
            userObj = User.objects.get(hashedID=clientID)
            if UserDetails.email in userObj.details:
                return userObj.details[UserDetails.email]
            
            return None
        except Exception as e:
            logger.error(f"Error getting user email address: {str(e)}")
            return None


####################################################################################
class ProfileManagementOrganization(ProfileManagementBase):

    ##############################################
    @staticmethod
    def addUserIfNotExists(session, organization):
        """
        Add user if the entry doesn't already exists.

        :param session: POST request session
        :type session: Dictionary
        :return: User info for verification
        :rtype: User object

        """
        try:
            # create or fetch user as usual
            existingUser = ProfileManagementUser.addUserIfNotExists(session)
            if isinstance(existingUser, Exception):
                raise existingUser
            # then add this user to the organization
            existingUser.organizations.add(organization)
            if ProfileManagementOrganization.addUserToOrganization(existingUser, session["user"]["userinfo"]["org_id"]) == False:
                raise Exception(f"User could not be added to organization!, {existingUser}, {organization}")
            existingUser.save()
                
            return existingUser
        except (Exception) as error:
            logger.error(f"Error adding user : {str(error)}")
            return error

    ##############################################
    @staticmethod
    def addUserToOrganization(userToBeAdded:User, organizationID:str):
        """
        Add user to organization.

        :param userToBeAdded: User to be added
        :type userToBeAdded: User
        :param organization: id of the organization
        :type organization: str
        :return: flag if it worked or not
        :rtype: Bool

        """
        try:
            result = Organization.objects.get(subID=organizationID)
            result.users.add(userToBeAdded)
            if OrganizationDetails.addresses in result.details: # add addresses of the orga to the user
                for key in result.details[OrganizationDetails.addresses]:
                    userToBeAdded.details[UserDetails.addresses][key] = result.details[OrganizationDetails.addresses][key]
                userToBeAdded.save()
            result.save()
        except (ObjectDoesNotExist) as error:
            logger.error(f"Error adding user to organization, organization does not exist: {str(error)}")

            return False

        return True

    ##############################################
    @staticmethod
    def addOrGetOrganization(session):
        """
        Add organization if the entry doesn't already exists.

        :param session: POST request session
        :type session: Dictionary
        :param typeOfOrganization: type of the organization, can be: manufacturer, stakeholder
        :type typeOfOrganization: str
        :return: flag if it worked or not
        :rtype: Bool

        """
        orgaID = session["user"]["userinfo"]["org_id"]
        updated = timezone.now()
        try:
            # first get, then create
            resultObj = Organization.objects.get(subID=orgaID)
            return resultObj
        except (ObjectDoesNotExist) as error:
            try:
                orgaName = session[SessionContent.ORGANIZATION_NAME]
                orgaDetails = {OrganizationDetails.email: "", OrganizationDetails.addresses: {}, OrganizationDetails.taxID: "", OrganizationDetails.locale: "", OrganizationDetails.notificationSettings: {}, OrganizationDetails.priorities: {}}
                idHash = crypto.generateSecureID(orgaID)
                uri = ""
                supportedServices = [0]
                resultObj = Organization.objects.create(subID=orgaID, hashedID=idHash, supportedServices=supportedServices, name=orgaName, details=orgaDetails, uri=uri, updatedWhen=updated) 
                return resultObj
            except (Exception) as error:
                logger.error(f"Error adding organization: {str(error)}")
                return None
        except (Exception) as error:
            logger.error(f"Error getting or adding organization: {str(error)}")
            return None

    ##############################################
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
            
            for updateType in updates:
                details = updates[updateType]
                if updateType == OrganizationUpdateType.supportedServices:
                    assert isinstance(details, list), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of list"
                    existingInfo[OrganizationDescription.supportedServices] = details
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
                    # send to id manager
                    headers = {
                        'authorization': f'Bearer {auth0.apiToken.accessToken}',
                        'content-Type': 'application/json',
                        "Cache-Control": "no-cache"
                    }
                    baseURL = f"https://{settings.AUTH0_DOMAIN}"
                    payload = json.dumps({"display_name": details})
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
                elif updateType == OrganizationUpdateType.email:
                    assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                    existingInfo[OrganizationDescription.details][OrganizationDetails.email] = details
                elif updateType == OrganizationUpdateType.branding:
                    assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
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
                    response = handleTooManyRequestsError( lambda : requests.patch(f'{baseURL}/{auth0.auth0Config["APIPaths"]["APIBasePath"]}/{auth0.auth0Config["APIPaths"]["organizations"]}/{orgaID}', headers=headers, data=payload) )
                    if isinstance(response, Exception):
                        raise response
                elif updateType == OrganizationUpdateType.locale:
                    assert isinstance(details, str) and "-" in details, f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str or locale string was wrong"
                    existingInfo[OrganizationDescription.details][OrganizationDetails.locale] = details
                elif updateType == OrganizationUpdateType.taxID:
                    assert isinstance(details, str), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of str"
                    existingInfo[OrganizationDescription.details][OrganizationDetails.taxID] = details
                elif updateType == OrganizationUpdateType.notifications:
                    assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                    for notification in details:    
                        email = False
                        event = True    
                        if checkIfNestedKeyExists(details, notification, NotificationTargets.event):
                            email = details[notification][NotificationTargets.event]
                        if checkIfNestedKeyExists(details, notification, NotificationTargets.email):
                            event = details[notification][NotificationTargets.email]
                        existingInfo[OrganizationDescription.details][OrganizationDetails.notificationSettings][notification] = {NotificationTargets.email: email, NotificationTargets.event: event} 

                elif updateType == OrganizationUpdateType.priorities:
                    assert isinstance(details, dict), f"updateOrga failed because the wrong type for details was given: {type(details)} instead of dict"
                    existingInfo[OrganizationDescription.details][OrganizationDetails.priorities] = details
                else:
                    raise Exception("updateType not defined")
                
            affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], uri=existingInfo[OrganizationDescription.uri], updatedWhen=updated)
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
            for updateType in updates:
                details = updates[updateType]
                
                if updateType == OrganizationUpdateType.address:
                    assert isinstance(details, str), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of str"
                    del existingInfo[OrganizationDescription.details][OrganizationDetails.addresses][details]
                elif updateType == OrganizationUpdateType.supportedServices:
                    assert isinstance(details, list), f"deleteContent failed because the wrong type for details was given: {type(details)} instead of list"
                    for serviceNumber in details:
                        del existingInfo[OrganizationDescription.supportedServices][serviceNumber]
                else:
                    raise Exception("updateType not defined")
            
            affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], uri=existingInfo[OrganizationDescription.uri], updatedWhen=updated)
            return None
        except (Exception) as error:
            logger.error(f"Error deleting orga details: {str(error)}")
            return error

    ##############################################
    @staticmethod
    def getClientID(session):
        """
        Get ID of current client (can be organization or user)
        :param session: request session
        :type session: dict
        :return: hashed ID
        :rtype: String

        """
        return ProfileManagementBase.getOrganization(session)[OrganizationDescription.hashedID]

    ##############################################
    @staticmethod
    def getEMailAddress(clientID:str) -> str | None:
        """
        Get Mail address of orga if available

        :param clientID: The hashed ID of the orga
        :type clientID: str
        :return: E-Mail address or None
        :rtype: str | None
        """
        try:
            orgaObj = Organization.objects.get(hashedID=clientID)
            if OrganizationDetails.email in orgaObj.details:
                return orgaObj.details[OrganizationDetails.email]
            
            return None
        except Exception as e:
            logger.error(f"Error getting orga email address: {str(e)}")
            return None
        
    ##############################################
    @staticmethod
    def getSupportedServices(clientID:str) -> list[int]:
        """
        Get a list of all services of the organization

        :param clientID: The hashed ID of the orga
        :type clientID: str
        :return: list of all services as integers (see services.py)
        :rtype: list[int]
        
        """
        try:
            orgaObj = Organization.objects.get(hashedID=clientID)
            return orgaObj.supportedServices
        except Exception as e:
            logger.error(f"Error getting orgas supported services: {str(e)}")
            return []

profileManagement= {ProfileClasses.user: ProfileManagementUser(), ProfileClasses.organization: ProfileManagementOrganization()}