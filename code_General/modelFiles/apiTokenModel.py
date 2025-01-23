"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Model for all api tokens
 Could have used the drf variant but would then have to use django admin and user accounts as well which sucks because we already have an ID Manager (auth0)
"""

import binascii
import copy
import json, enum
import os
from django.db import models
from django.contrib.postgres.fields import ArrayField

from ..utilities.crypto import generateURLFriendlyRandomString
from ..utilities.customStrEnum import StrEnumExactlyAsDefined

##################################################
class APITokenDescription(StrEnumExactlyAsDefined):
    """
    The model consists of the following:
    """
    user = enum.auto()
    organization = enum.auto()
    admin = enum.auto()
    token = enum.auto()
    createdWhen = enum.auto()


###################################################
class APIToken(models.Model):
    """
    Management class for API Tokens.
    
    :user: User linked to that token...
    :organization: ... or organization linked to that token
    :admin: Boolean whether the user is an admin or not
    :token: Created url friendly token for that user
    :createdWhen: Automatically assigned date and time(UTC+0) when the entry is created
    """
    user = models.OneToOneField("User", on_delete=models.CASCADE, blank=True, null=True)
    organization = models.OneToOneField("Organization", on_delete=models.CASCADE, blank=True, null=True)
    admin = models.BooleanField(default=False)
    token = models.CharField(max_length=512, primary_key=True)
    createdWhen = models.DateTimeField(auto_now_add=True)

    ##################################################
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = generateURLFriendlyRandomString()
        return super().save(*args, **kwargs)

    ###################################################
    def __str__(self):
        return self.user.__str__ + " " + self.organization.__str__ + " " + str(self.admin) + " " +  self.token + " " + str(self.createdWhen)

    ###################################################
    def toDict(self):
        return {
            APITokenDescription.user: self.user,
            APITokenDescription.organization: self.organization,
            APITokenDescription.admin: self.admin,
            APITokenDescription.token: self.token,
            APITokenDescription.createdWhen: str(self.createdWhen)
        }
