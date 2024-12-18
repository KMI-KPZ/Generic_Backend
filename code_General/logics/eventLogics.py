"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for Events
"""
import logging

from ..definitions import *
from ..connections.postgresql import pgProfiles, pgEvents

from django.conf import settings


from ..connections.mailer import MailingClass


from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForCreateEvent(validatedInput, request):
    if EventsDescriptionGeneric.userHashedID in validatedInput:
        userHashedID = validatedInput[EventsDescriptionGeneric.userHashedID]
    else:
        userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)

    retVal = pgEvents.createEventEntry(userHashedID=userHashedID, eventType=validatedInput[EventsDescriptionGeneric.eventType], eventData=validatedInput[EventsDescriptionGeneric.eventData], triggerEvent=validatedInput[EventsDescriptionGeneric.triggerEvent])
    if isinstance(retVal, Exception):
        raise retVal
    return retVal    

##############################################
def logicForDeleteAllEventsForAUser(request):
    userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)
    retVal = pgEvents.removeAllEventsForUser(userHashedID)
    if isinstance(retVal, Exception):
        raise retVal
    
##############################################
def logicForDeleteOneEvent(eventID):
    retVal = pgEvents.removeEvent(eventID)
    if isinstance(retVal, Exception):
        raise retVal
    
##############################################
def logicForGetOneEventOfUser(eventID):
    event = pgEvents.getOneEvent(eventID)
    if isinstance(event, Exception):
        raise event
    return event

##############################################
def logicForGetAllEventsForUser(request):
    userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)
    listOfEvents = pgEvents.getAllEventsOfAUser(userHashedID)
    if isinstance(listOfEvents, Exception):
        raise listOfEvents
    return listOfEvents