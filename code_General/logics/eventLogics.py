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
    try:
        if EventsDescriptionGeneric.userHashedID in validatedInput:
            userHashedID = validatedInput[EventsDescriptionGeneric.userHashedID]
        else:
            userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)

        retVal = pgEvents.createEventEntry(userHashedID=userHashedID, eventType=validatedInput[EventsDescriptionGeneric.eventType], eventData=validatedInput[EventsDescriptionGeneric.eventData], triggerEvent=validatedInput[EventsDescriptionGeneric.triggerEvent])
        if isinstance(retVal, Exception):
            raise retVal
        return (retVal, None, 200)    

    except Exception as e:
        loggerError.error(f"Error in {logicForCreateEvent.__name__}: {str(e)}")
        return (None, e, 500)
    
##############################################
def logicForDeleteAllEventsForAUser(request):
    try:
        userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)
        retVal = pgEvents.removeAllEventsForUser(userHashedID)
        if isinstance(retVal, Exception):
            raise retVal
        return (None, 200)

    except Exception as e:
        loggerError.error(f"Error in {logicForDeleteAllEventsForAUser.__name__}: {str(e)}")
        return (e, 500)
    
##############################################
def logicForDeleteOneEvent(eventID): 
    try:
        retVal = pgEvents.removeEvent(eventID)
        if isinstance(retVal, Exception):
            raise retVal
        return (None, 200)
    
    except Exception as e:
        loggerError.error(f"Error in {logicForDeleteOneEvent.__name__}: {str(e)}")
        return (e, 500)
    
##############################################
def logicForGetOneEventOfUser(eventID):
    try:
        event = pgEvents.getOneEvent(eventID)
        if isinstance(event, Exception):
            raise event
        return (event, None, 200)
    
    except Exception as e:
        loggerError.error(f"Error in {logicForGetOneEventOfUser.__name__}: {str(e)}")
        return (None, e, 500)

##############################################
def logicForGetAllEventsForUser(request):
    try:
        userHashedID = pgProfiles.ProfileManagementBase.getUserHashID(request.session)
        listOfEvents = pgEvents.getAllEventsOfAUser(userHashedID)
        if isinstance(listOfEvents, Exception):
            raise listOfEvents
        return (listOfEvents, None, 200)
    
    except Exception as e:
        loggerError.error(f"Error in {logicForGetAllEventsForUser.__name__}: {str(e)}")
        return (None, e, 500)