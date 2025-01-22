"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Model for organizations
"""
import copy
import json, enum
from django.db import models
from django.contrib.postgres.fields import ArrayField

from ..utilities.customStrEnum import StrEnumExactlyAsDefined

###################################################
class OrganizationDescription(StrEnumExactlyAsDefined):
    """
    What does an Organization consists of?

    """
    subID =enum.auto()
    hashedID = enum.auto()
    name = enum.auto()
    details = enum.auto()
    users = enum.auto()
    supportedServices = enum.auto()
    uri = enum.auto()
    createdWhen = enum.auto()
    updatedWhen = enum.auto()
    accessedWhen = enum.auto()


###################################################
# Enum for Content of details for organizations
class OrganizationDetails(StrEnumExactlyAsDefined):
    """
    What details can an organization have?
    
    """
    addresses = enum.auto()
    email = enum.auto()
    taxID = enum.auto()
    locale = enum.auto() # preferred communication language
    branding = enum.auto()
    notificationSettings = enum.auto()
    priorities = enum.auto()
    services = enum.auto()

###################################################
# Enum what can be updated for a user
class OrganizationUpdateType(StrEnumExactlyAsDefined):
    """
    What updated can happen to a user?
    
    """
    displayName = enum.auto()
    email = enum.auto()
    branding = enum.auto()
    supportedServices = enum.auto()
    services = enum.auto()
    notifications = enum.auto()
    locale = enum.auto()
    address = enum.auto()
    priorities = enum.auto()
    taxID = enum.auto()

###################################################
# Enum for notification settings for orgas
class OrganizationNotificationSettings(StrEnumExactlyAsDefined):
    """
    Which notifications can be received?
    Some can be set here but most are specific to the plattform itself
    
    """
    newsletter = enum.auto() 

###################################################
# Enum for notification targets for users
class OrganizationNotificationTargets(StrEnumExactlyAsDefined):
    """
    What is the target for each notification?
    
    """
    email = enum.auto()	
    event = enum.auto()

###################################################
# Enum for priorities for orgas
class OrganizationPriorities(StrEnumExactlyAsDefined):
    """
    If the organization has some priorities, they can be set here
    Is used in Semper-KI for calculations, can be used here for whatever
    """
    pass

#Table for Organizations
###################################################
class Organization(models.Model):
    """
    Profile management class for organizations.
    
    :subID: Unique ID for that person returned by Auth0, primary key
    :hashedID: SHA-512 hashed value of the subID for anonymous identification
    :name: Nickname returned by Auth0, used for filter searches in DB
    :details: Address, tax id and so on
    :users: Link to users belonging to that organization
    :supportedServices: Array of service codes that this organization supports
    :uri: Representation link inside the knowledge graph
    :createdWhen: Automatically assigned date and time(UTC+0) when the entry is created
    :updatedWhen: Date and time at which the entry was updated
    :accessedWhen: Last date and time the data was fetched from the database, automatically set
    """
    subID = models.CharField(primary_key=True,max_length=100)
    hashedID = models.CharField(max_length=513)
    name = models.CharField(max_length=100)
    details = models.JSONField()
    users = models.ManyToManyField("User")
    supportedServices = ArrayField(models.IntegerField())
    uri = models.CharField(max_length=200) #maybe use this for api key instead
    createdWhen = models.DateTimeField(auto_now_add=True)
    updatedWhen = models.DateTimeField()
    accessedWhen = models.DateTimeField(auto_now=True)

    ###################################################
    class Meta:
        indexes = [
            models.Index(fields=["hashedID"], name="organization_idx"),
        ]

    ###################################################
    def __str__(self):
        return self.hashedID + " " + self.name + " " + json.dumps(self.details) + " " + " " + str(self.supportedServices) + " " + str(self.createdWhen) + " " + str(self.updatedWhen) + " " + str(self.accessedWhen)

    ###################################################
    def toDict(self):
        return {OrganizationDescription.hashedID: self.hashedID, 
                OrganizationDescription.name: self.name, 
                OrganizationDescription.details: self.details, 
                OrganizationDescription.supportedServices: self.supportedServices, 
                OrganizationDescription.createdWhen: str(self.createdWhen), 
                OrganizationDescription.updatedWhen: str(self.updatedWhen), 
                OrganizationDescription.accessedWhen: str(self.accessedWhen)}

    ###################################################
    def initializeDetails(self):
        """
        Fill JSON field with necessary details

        :return: Organzation
        :rtype: Organzation

        """
        self.details = {
            OrganizationDetails.email: "",
            OrganizationDetails.locale: "",
            OrganizationDetails.taxID: "",
            OrganizationDetails.addresses: {},
            OrganizationDetails.notificationSettings: {"organization": {OrganizationNotificationSettings.newsletter: {OrganizationNotificationTargets.email: True, OrganizationNotificationTargets.event: True}}},
            OrganizationDetails.priorities: {}
        }
        self.save()
        return self
    
    ###################################################
    def updateDetails(self):
        """
        Fill existing JSON field with necessary details from an old entry or initialize new ones
        
        :return: Organzation
        :rtype: Organzation
        """
        existingDetails = copy.deepcopy(self.details)
        self.details = {}
        if OrganizationDetails.email in existingDetails and isinstance(existingDetails[OrganizationDetails.email], str):
            self.details[OrganizationDetails.email] = existingDetails[OrganizationDetails.email]
        else:
            self.details[OrganizationDetails.email] = ""
        if OrganizationDetails.locale in existingDetails and isinstance(existingDetails[OrganizationDetails.locale], str):
            self.details[OrganizationDetails.locale] = existingDetails[OrganizationDetails.locale]
        else:
            self.details[OrganizationDetails.locale] = ""
        if OrganizationDetails.taxID in existingDetails and isinstance(existingDetails[OrganizationDetails.taxID], str):
            self.details[OrganizationDetails.taxID] = existingDetails[OrganizationDetails.taxID]
        else:
            self.details[OrganizationDetails.taxID] = ""
        if OrganizationDetails.addresses in existingDetails and isinstance(existingDetails[OrganizationDetails.addresses], dict):
            self.details[OrganizationDetails.addresses] = existingDetails[OrganizationDetails.addresses]
        else:
            self.details[OrganizationDetails.addresses] = {}
        if OrganizationDetails.priorities in existingDetails and isinstance(existingDetails[OrganizationDetails.priorities], dict):
            self.details[OrganizationDetails.priorities] = existingDetails[OrganizationDetails.priorities]
        else:
            self.details[OrganizationDetails.priorities] = {}
        if OrganizationDetails.branding in existingDetails and isinstance(existingDetails[OrganizationDetails.priorities], dict):
            self.details[OrganizationDetails.branding] = existingDetails[OrganizationDetails.branding]
        else:
            self.details[OrganizationDetails.branding] = {"logo_url": "", "colors": {"primary": "#000000", "page_background": "#FFFFFF"}}
        if OrganizationDetails.services in existingDetails and isinstance(existingDetails[OrganizationDetails.services], dict):
            self.details[OrganizationDetails.services] = existingDetails[OrganizationDetails.services]
        else:
            self.details[OrganizationDetails.services] = {}
        if OrganizationDetails.notificationSettings in existingDetails and isinstance(existingDetails[OrganizationDetails.notificationSettings], dict):
            self.details[OrganizationDetails.notificationSettings] = {"organization": {}}
            if "organization" in existingDetails[OrganizationDetails.notificationSettings]:
                for entry in existingDetails[OrganizationDetails.notificationSettings]["organization"]:
                    existingNotificationSetting = existingDetails[OrganizationDetails.notificationSettings]
                    if entry in OrganizationNotificationSettings.__members__:
                        self.details[OrganizationDetails.notificationSettings]["organization"][entry] = {}
                        if OrganizationNotificationTargets.email in existingNotificationSetting["organization"][entry]:
                            self.details[OrganizationDetails.notificationSettings]["organization"][entry][OrganizationNotificationTargets.email] = existingNotificationSetting["organization"][entry][OrganizationNotificationTargets.email]
                        else:
                            self.details[OrganizationDetails.notificationSettings]["organization"][entry][OrganizationNotificationTargets.email] = True
                        if OrganizationNotificationTargets.event in existingNotificationSetting["organization"][entry]:
                            self.details[OrganizationDetails.notificationSettings]["organization"][entry][OrganizationNotificationTargets.event] = existingNotificationSetting["organization"][entry][OrganizationNotificationTargets.event]
                        else:
                            self.details[OrganizationDetails.notificationSettings]["organization"][entry][OrganizationNotificationTargets.event] = True
                    else:
                        self.details[OrganizationDetails.notificationSettings]["organization"][entry] = existingNotificationSetting["organization"][entry]
            else:
                self.details[OrganizationDetails.notificationSettings]["organization"][OrganizationNotificationSettings.newsletter] = {OrganizationNotificationTargets.email: True, OrganizationNotificationTargets.event: True}

        self.save()
        return self