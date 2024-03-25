"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for database calls to manage a user/organization profile
"""
import types, json, enum, re

from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from ...modelFiles.organizationModel import Organization
from ...modelFiles.userModel import User
from ...utilities import crypto
from logging import getLogger

from ...definitions import SessionContent, UserDescription, OrganizationDescription, ProfileClasses, GlobalDefaults, UserDetails, OrganizationDetails

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
    def getOrganization(session):
        """
        Check whether an organization exists or not and retrieve information.

        :param session: session
        :type session: Dictionary
        :return: Organization details from database
        :rtype: Dictionary

        """
        orgaID = session["user"]["userinfo"]["org_id"]
        obj = {}
        try:
            obj = Organization.objects.get(subID=orgaID).toDict()
        except (Exception) as error:
            logger.error(f"Error getting organization: {str(error)}")

        return obj
    
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
        Retrieve Organization name via hashID

        :param session: session
        :type session: Str
        :return: Name of the organization
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
    def getUserKeyViaHash(hashedID):
        """
        Retrieve User ID via Database and hashkey

        :param hashedID: hashed ID
        :type hashedID: str
        :return: Orga key from database
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
        Retrieve User Object via Database and hashkey

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
        except (Exception) as error:
            logger.error(f"Error setting user locale: {str(error)}")

    ##############################################
    @staticmethod
    def getUserLocale(session):
        """
        Gets the locale of the user from the profile or session.

        :param session: session
        :type session: Dictionary-like object
        :return: Locale
        :rtype: Str
        
        """
        try:
            if "user" in session:
                userID = session["user"]["userinfo"]["sub"]
                userObj = User.objects.get(subID=userID)
                if userObj != None:
                    return userObj.details[UserDetails.locale]
                else:
                    return "de-DE"
            elif SessionContent.LOCALE in session:
                return session[SessionContent.LOCALE]
            else:
                return "de-DE"
        except (Exception) as error:
            logger.error(f"Error getting user locale: {str(error)}")
            return "de-DE"



    ##############################################
    @staticmethod
    def deleteUser(session, uHashedID=""):
        """
        Delete User.

        :param session: GET request session
        :type session: Dictionary
        :return: Flag if it worked or not
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
        :return: Flag if it worked or not
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
    def checkIfUserIsInOrganization(session):
        """
        Check if a user is in an organization or not. Can be used to decide if additional code specific for orgas should be run

        :param session: GET request session
        :type session: Dictionary
        :return: True if User is in organization, False if not
        :rtype: bool
        
        """
        if "user" in session and "org_id" in session["user"]["userinfo"]:
            return True
        return False

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

            return result

        except (ObjectDoesNotExist) as error:
            try:
                userName = session["user"]["userinfo"]["nickname"]
                userEmail = session["user"]["userinfo"]["email"]
                details = {UserDetails.email: userEmail}
                updated = timezone.now()
                lastSeen = timezone.now()
                idHash = crypto.generateSecureID(userID)
                 
                createdUser = User.objects.create(subID=userID, hashedID=idHash, name=userName, details=details, updatedWhen=updated, lastSeen=lastSeen)

                return createdUser
            except (Exception) as error:
                logger.error(f"Error adding user : {str(error)}")
                return error

    ##############################################
    @staticmethod
    def updateContent(session, details, userID=""):
        """
        Update user details.

        :param session: GET request session
        :type session: Dictionary
        :return: Flag if it worked or not
        :rtype: Bool

        """
        if userID == "":
            subID = session["user"]["userinfo"]["sub"]
        else:
            subID = userID
        updated = timezone.now()
        try:
            existingObj = User.objects.get(subID=subID)
            existingInfo = {UserDescription.name: existingObj.name, UserDescription.details: existingObj.details}
            for key in details:
                existingInfo[key] = details[key]
            affected = User.objects.filter(subID=subID).update(details=existingInfo[UserDescription.details], name=existingInfo[UserDescription.name], updatedWhen=updated)
        except (Exception) as error:
            logger.error(f"Error updating user details: {str(error)}")
            return False
        return True
    
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
    def getEMailAdress(clientID:str) -> str | None:
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

        userID = session["user"]["userinfo"]["sub"]
        try:
            # first get, if it fails, create
            existingUser = User.objects.get(subID=userID)
        except (ObjectDoesNotExist) as error:
            try:
                userName = session["user"]["userinfo"]["nickname"]
                userEmail = session["user"]["userinfo"]["email"]
                details = {OrganizationDetails.email: userEmail}
                updated = timezone.now()
                lastSeen = timezone.now()
                idHash = crypto.generateSecureID(userID)
                 
                existingUser = User.objects.create(subID=userID, hashedID=idHash, name=userName, details=details, updatedWhen=updated, lastSeen=lastSeen)
            except (Exception) as error:
                logger.error(f"Error adding user : {str(error)}")
                return error
        try:
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
    def addUserToOrganization(userToBeAdded, organizationID):
        """
        Add user to organization.

        :param userToBeAdded: User to be added
        :type userToBeAdded: User
        :param organization: id of the organization
        :type organization: str
        :return: Flag if it worked or not
        :rtype: Bool

        """
        try:
            result = Organization.objects.get(subID=organizationID)
            result.users.add(userToBeAdded)
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
        :return: Flag if it worked or not
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
                orgaDetails = {OrganizationDetails.email: "", OrganizationDetails.address: "", OrganizationDetails.taxID: ""}
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
    def updateContent(session, content, orgaID=""):
        """
        Update user details and more.

        :param session: GET request session
        :type session: Dictionary
        :return: Flag if it worked or not
        :rtype: Bool

        """
        if orgaID == "":
            orgID = session["user"]["userinfo"]["org_id"]
        else:
            orgID = orgaID
        updated = timezone.now()
        try:
            existingObj = Organization.objects.get(subID=orgID)
            existingInfo = {OrganizationDescription.details: existingObj.details, OrganizationDescription.supportedServices: existingObj.supportedServices, OrganizationDescription.name: existingObj.name, OrganizationDescription.uri: existingObj.uri}
            for key in content:
                if key == OrganizationDescription.supportedServices:
                    existingInfo[OrganizationDescription.supportedServices] = content[key]
                else:
                    existingInfo[key] = content[key]
            affected = Organization.objects.filter(subID=orgID).update(details=existingInfo[OrganizationDescription.details], supportedServices=existingInfo[OrganizationDescription.supportedServices], name=existingInfo[OrganizationDescription.name], uri=existingInfo[OrganizationDescription.uri], updatedWhen=updated)
        except (Exception) as error:
            logger.error(f"Error updating organization details: {str(error)}")
            return False
        return True

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
    def getEMailAdress(clientID:str) -> str | None:
        """
        Get Mail address of user if available

        :param clientID: The hashed ID of the user
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
            logger.error(f"Error getting user email address: {str(e)}")
            return None

profileManagement= {ProfileClasses.user: ProfileManagementUser(), ProfileClasses.organization: ProfileManagementOrganization()}