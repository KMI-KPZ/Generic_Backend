"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Models for events
"""

import enum
from django.db import models

from ..utilities.customStrEnum import StrEnumExactlyAsDefined

##################################################
class EventDescription(StrEnumExactlyAsDefined):
    """
    What does an event entry consists of?
    
    """
    eventID = enum.auto()
    eventType = enum.auto()
    userHashedID = enum.auto()
    eventData = enum.auto()
    createdWhen = enum.auto()
    triggerEvent = enum.auto()

##################################################
class Event(models.Model):
    """
    Event database class

    :eventID: Primary key
    :eventType: The type of the event, e.g. processEvent
    :userHashedID: ID of the user that is the recipient of the event
    :eventData: The event itself
    :createdWhen: Automatically assigned date and time(UTC+0) when the entry is created
    :triggerEvent: Should the event trigger a popup?

    """
    eventID = models.CharField(primary_key=True, max_length=513)
    eventType = models.CharField(max_length=200)
    userHashedID = models.CharField(max_length=513)
    eventData = models.JSONField()
    createdWhen = models.DateTimeField(auto_now_add=True)
    triggerEvent = models.BooleanField()

    ###################################################
    class Meta:
        ordering = ["createdWhen"]
        indexes = [
            models.Index(fields=["userHashedID"], name="event_user_idx")
        ]

    ##################################################
    def __str__(self):
        return f"{self.eventID},{self.eventType},{self.userHashedID},{self.eventData},{self.createdWhen}, {self.triggerEvent}"
    
    ##################################################
    def toDict(self):
        return {
            EventDescription.eventID: self.eventID,
            EventDescription.eventType: self.eventType,
            EventDescription.userHashedID: self.userHashedID,
            EventDescription.eventData: self.eventData,
            EventDescription.createdWhen: str(self.createdWhen),
            EventDescription.triggerEvent: self.triggerEvent
        }