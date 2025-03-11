"""
Generic Backend

Silvio Weging 2024

Contains: Access to the event database
"""

import logging

from ...utilities import crypto

from ...models import Event, EventDescription


logger = logging.getLogger("errors")
##################################################
def createEventEntry(userHashedID:str, eventType:str, eventData:dict, triggerEvent:bool) -> dict | Exception:
    """
    Saves the event to the database

    :param userHashedID: The hashed id of the user to which the event belongs
    :type userHashedID: str
    :param event: The event to be saved to the database
    :type event: Dict
    :return: The created Object
    :rtype: dict | Exception
    """
    try:
        eventID = crypto.generateURLFriendlyRandomString()
        createdObj = Event.objects.create(eventID=eventID, userHashedID=userHashedID, eventType=eventType, eventData=eventData, triggerEvent=triggerEvent)
        return createdObj.toDict()
    except (Exception) as error:
        logger.error(f'could not create event entry: {str(error)}')
        return error
    
##################################################
def getOneEvent(eventID:str) -> dict | Exception:
    """
    Return one event

    :param eventID: The ID of the event
    :type eventID: str
    :return: Event itself
    :rtype: Dict
    
    """
    try:
        eventObj = Event.objects.get(eventID=eventID)
        return eventObj.toDict()
    except (Exception) as error:
        logger.error(f'could not get event entry: {str(error)}')
        return error
    
##################################################
def getAllEventsOfAUser(userHashedID:str) -> list:
    """
    Return all events of a user

    :param userHashedID: The hashed ID of the user
    :type userHashedID: str
    :return: list of entries for that user
    :rtype: list[dict]
    
    """
    try:
        events = Event.objects.filter(userHashedID=userHashedID)
        return [entry.toDict() for entry in events]
    except (Exception) as error:
        logger.error(f'could not get events for user: {str(error)}')
        return error	
    
##################################################
def removeEvent(eventID:str) -> None | Exception:
    """
    Remove event

    :param eventID: The event ID
    :type eventID: str
    :return: None
    :rtype: None | Exception
    
    """
    try:
        event = Event.objects.get(eventID=eventID)
        event.delete()
    except (Exception) as error:
        logger.error(f'Could not delete event: {str(error)}')
        return error	
    
##################################################
def removeAllEventsForUser(userHashedID:str) -> None | Exception:
    """
    Remove all events for a user

    :param userHashedID: The user's hashed ID
    :type userHashedID: str
    :return: None
    :rtype: None | Exception
    
    """	
    try:
        events = Event.objects.filter(userHashedID=userHashedID)
        for event in events:
            event.delete()
    except (Exception) as error:
        logger.error(f'Could not remove all events for user	{str(error)}')	
        return error