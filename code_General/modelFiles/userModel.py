"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Model for user
"""
import json, enum
from django.utils import timezone
from django.db import models
from django.contrib.postgres.fields import ArrayField

from ..utilities.customStrEnum import StrEnumExactylAsDefined

import code_General.modelFiles.organizationModel as orgaModel #must be imported that way to avoid cyclic imports

###################################################
class UserDescription(StrEnumExactylAsDefined):
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


# Table for regular Users
###################################################
class User(models.Model):
    """
    Profile management class for regular users.
    
    :subID: Unique ID for that person returned by Auth0, primary key
    :hashedID: SHA-512 hashed value of the subID for anonymous identification
    :name: Nickname returned by Auth0, used for filter searches in DB
    :organizations: The organizations that the user belongs to
    :details: Adress, E-Mail, ...
    :createdWhen: Automatically assigned date and time(UTC+0) when the user first registered
    :updatedWhen: Date and time at which the entry was updated
    :accessedWhen: Last date and time the user was fetched from the database, automatically set
    :lastSeen: When was the user last online, set manually
    """
    subID = models.CharField(primary_key=True,max_length=100)
    hashedID = models.CharField(max_length=513)
    name = models.CharField(max_length=100)
    organizations = models.ManyToManyField(orgaModel.Organization)
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
        return self.hashedID + " " + self.name + " " + str(self.organizations) + " " + json.dumps(self.details) + " " + str(self.createdWhen) + " " + str(self.updatedWhen) + " " + str(self.accessedWhen) + " " + str(self.lastSeen)

    ###################################################
    def toDict(self):
        return {UserDescription.hashedID: self.hashedID, 
                UserDescription.name: self.name, 
                UserDescription.organizations: ','.join(orga.hashedID for orga in self.organizations.all()), 
                UserDescription.details: self.details, 
                UserDescription.createdWhen: str(self.createdWhen), 
                UserDescription.updatedWhen: str(self.updatedWhen), 
                UserDescription.accessedWhen: str(self.accessedWhen), 
                UserDescription.lastSeen: str(self.lastSeen)}
