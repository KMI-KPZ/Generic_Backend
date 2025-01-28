"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Model for user
"""
import copy
import json, enum
from django.utils import timezone
from django.db import models
from django.contrib.postgres.fields import ArrayField

from ..utilities.customStrEnum import StrEnumExactlyAsDefined

###################################################
class UserDescription(StrEnumExactlyAsDefined):
    """
    What does a user consists of?
    
    """
    subID = enum.auto()
    hashedID = enum.auto()
    name = enum.auto()
    organizations = enum.auto()
    details = enum.auto()
    createdWhen = enum.auto()
    updatedWhen = enum.auto()
    accessedWhen = enum.auto()
    lastSeen = enum.auto()

###################################################
# Enum for Content of details for users
class UserDetails(StrEnumExactlyAsDefined):
    """
    What details can a user have
    
    """
    email = enum.auto()
    addresses = enum.auto()
    locale = enum.auto()
    notificationSettings = enum.auto()
    statistics = enum.auto()

###################################################
# Enum for notification settings for users
class UserNotificationSettings(StrEnumExactlyAsDefined):
    """
    Which notifications can be received?
    Some can be set here but most are specific to the plattform itself (just inherit from this class)
    
    """
    newsletter = enum.auto() 

###################################################
# Enum for notification targets for users
class UserNotificationTargets(StrEnumExactlyAsDefined):
    """
    What is the target for each notification?
    
    """
    email = enum.auto()	
    event = enum.auto()

###################################################
# Enum for statistics settings for user profiles
class UserStatistics(StrEnumExactlyAsDefined):
    """
    Which statistics are measured?
    
    """
    lastLogin = enum.auto()
    numberOfLoginsTotal = enum.auto()
    locationOfLastLogin = enum.auto()

###################################################
# Enum what can be updated for a user
class UserUpdateType(StrEnumExactlyAsDefined):
    """
    What updated can happen to a user?
    
    """
    displayName = enum.auto()
    email = enum.auto()
    notifications = enum.auto()
    locale = enum.auto()
    address = enum.auto()

# Table for regular Users
###################################################
class User(models.Model):
    """
    Profile management class for regular users.
    
    :subID: Unique ID for that person returned by Auth0, primary key
    :hashedID: SHA-512 hashed value of the subID for anonymous identification
    :name: Nickname returned by Auth0, used for filter searches in DB
    :organizations: The organizations that the user belongs to
    :details: Address, E-Mail, ...
    :createdWhen: Automatically assigned date and time(UTC+0) when the user first registered
    :updatedWhen: Date and time at which the entry was updated
    :accessedWhen: Last date and time the user was fetched from the database, automatically set
    :lastSeen: When was the user last online, set manually
    """
    subID = models.CharField(primary_key=True,max_length=100)
    hashedID = models.CharField(max_length=513)
    name = models.CharField(max_length=100)
    organizations = models.ManyToManyField("Organization")
    details = models.JSONField()
    createdWhen = models.DateTimeField(auto_now_add=True)
    updatedWhen = models.DateTimeField(default=timezone.now)
    accessedWhen = models.DateTimeField(auto_now=True)
    lastSeen = models.DateTimeField(default=timezone.now)

    ###################################################
    class Meta:
        indexes = [
            models.Index(fields=["hashedID"], name="user_idx"),
        ]

    ###################################################
    def __str__(self):
        """
        Return string representation
        """
        return self.hashedID + " " + self.name + " " + str(self.organizations) + " " + json.dumps(self.details) + " " + str(self.createdWhen) + " " + str(self.updatedWhen) + " " + str(self.accessedWhen) + " " + str(self.lastSeen)

    ###################################################
    def toDict(self):
        """
        Return dictionary representation
        """
        return {UserDescription.hashedID: self.hashedID, 
                UserDescription.name: self.name, 
                UserDescription.organizations: ','.join(orga.hashedID for orga in self.organizations.all()), 
                UserDescription.details: self.details, 
                UserDescription.createdWhen: str(self.createdWhen), 
                UserDescription.updatedWhen: str(self.updatedWhen), 
                UserDescription.accessedWhen: str(self.accessedWhen), 
                UserDescription.lastSeen: str(self.lastSeen)}

    ###################################################
    def initializeDetails(self):
        """
        Fill JSON field with necessary details

        :return: User
        :rtype: User

        """
        self.details = {
            UserDetails.email: "",
            UserDetails.addresses: {},
            UserDetails.locale: "",
            UserDetails.statistics: {UserStatistics.lastLogin: "", UserStatistics.locationOfLastLogin: "", UserStatistics.numberOfLoginsTotal: 0},
            UserDetails.notificationSettings: {"user":{UserNotificationSettings.newsletter: {UserNotificationTargets.email: True, UserNotificationTargets.event: True}}, "organization": {}}
        }
        self.save()
        return self
    
    ###################################################
    def updateDetails(self):
        """
        Fill existing JSON field with necessary details from an old entry or initialize new ones
        
        :return: User
        :rtype: User

        """
        existingDetails = copy.deepcopy(self.details)
        self.details = {}
        if UserDetails.email in existingDetails and isinstance(existingDetails[UserDetails.email], str):
            self.details[UserDetails.email] = existingDetails[UserDetails.email]
        else:
            self.details[UserDetails.email] = ""
        if UserDetails.locale in existingDetails and isinstance(existingDetails[UserDetails.locale], str):
            self.details[UserDetails.locale] = existingDetails[UserDetails.locale]
        else:
            self.details[UserDetails.locale] = ""
        if UserDetails.addresses in existingDetails and isinstance(existingDetails[UserDetails.addresses], dict):
            self.details[UserDetails.addresses] = existingDetails[UserDetails.addresses]
        else:
            self.details[UserDetails.addresses] = {}
        if UserDetails.statistics in existingDetails and isinstance(existingDetails[UserDetails.statistics], dict):
            self.details[UserDetails.statistics] = {}
            if UserStatistics.lastLogin in existingDetails[UserDetails.statistics]:
                self.details[UserDetails.statistics][UserStatistics.lastLogin] = existingDetails[UserDetails.statistics][UserStatistics.lastLogin]
            else:
                self.details[UserDetails.statistics][UserStatistics.lastLogin] = ""
            if UserStatistics.locationOfLastLogin in existingDetails[UserDetails.statistics]:
                self.details[UserDetails.statistics][UserStatistics.locationOfLastLogin] = existingDetails[UserDetails.statistics][UserStatistics.locationOfLastLogin]
            else:
                self.details[UserDetails.statistics][UserStatistics.lastLogin] = ""
            if UserStatistics.numberOfLoginsTotal in existingDetails[UserDetails.statistics]:
                self.details[UserDetails.statistics][UserStatistics.numberOfLoginsTotal] = existingDetails[UserDetails.statistics][UserStatistics.numberOfLoginsTotal]
            else:
                self.details[UserDetails.statistics][UserStatistics.numberOfLoginsTotal] = 0
        else:
            self.details[UserDetails.statistics] = {UserStatistics.lastLogin: "", UserStatistics.locationOfLastLogin: "", UserStatistics.numberOfLoginsTotal: 0}
        if UserDetails.notificationSettings in existingDetails and isinstance(existingDetails[UserDetails.notificationSettings], dict):
            self.details[UserDetails.notificationSettings] = {"user": {}}
            if "user" in existingDetails[UserDetails.notificationSettings]:
                for entry in existingDetails[UserDetails.notificationSettings]["user"]:
                    existingNotificationSetting = existingDetails[UserDetails.notificationSettings]
                    if entry in UserNotificationSettings.__members__:
                        self.details[UserDetails.notificationSettings]["user"][entry] = {}
                        if UserNotificationTargets.email in existingNotificationSetting["user"][entry]:
                            self.details[UserDetails.notificationSettings]["user"][entry][UserNotificationTargets.email] = existingNotificationSetting["user"][entry][UserNotificationTargets.email]
                        else:
                            self.details[UserDetails.notificationSettings]["user"][entry][UserNotificationTargets.email] = True
                        if UserNotificationTargets.event in existingNotificationSetting["user"][entry]:
                            self.details[UserDetails.notificationSettings]["user"][entry][UserNotificationTargets.event] = existingNotificationSetting["user"][entry][UserNotificationTargets.event]
                        else:
                            self.details[UserDetails.notificationSettings]["user"][entry][UserNotificationTargets.event] = True
                    else:
                        self.details[UserDetails.notificationSettings]["user"][entry] = existingNotificationSetting["user"][entry]
            else:
                for entry in UserNotificationSettings:
                    self.details[UserDetails.notificationSettings]["user"][entry] = {UserNotificationTargets.email: True, UserNotificationTargets.event: True}
            if "organization" in existingDetails[UserDetails.notificationSettings]: # user is part of an organization
                self.details[UserDetails.notificationSettings]["organization"] = existingDetails[UserDetails.notificationSettings]["organization"]
        self.save()
        return self

