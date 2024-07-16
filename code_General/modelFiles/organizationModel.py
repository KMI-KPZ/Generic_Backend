"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Model for organizations
"""
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
