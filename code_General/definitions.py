"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Definitions, Classes, Enums to describe Elements in the Backend as well as Services
"""
import enum

from .utilities.customStrEnum import StrEnumExactlyAsDefined

from .modelFiles.organizationModel import OrganizationDescription, OrganizationDetails, OrganizationNotificationSettings, OrganizationNotificationTargets, OrganizationPriorities, OrganizationUpdateType
from .modelFiles.userModel import UserDescription, UserDetails, UserNotificationSettings, UserNotificationTargets, UserStatistics, UserUpdateType

#######################################################
# logging vocabulary
class Logging():
    class Subject(StrEnumExactlyAsDefined):
        USER = enum.auto()
        ADMIN = enum.auto()
        ORGANISATION = enum.auto()
        SYSTEM = enum.auto()
        SUBJECT = enum.auto() # for everything else

    class Predicate(StrEnumExactlyAsDefined):
        CREATED = enum.auto()
        DEFINED = enum.auto()
        FETCHED = enum.auto()
        EDITED = enum.auto()
        DELETED = enum.auto()
        PREDICATE = enum.auto() # for everything else

    class Object(StrEnumExactlyAsDefined):
        USER = enum.auto()
        ADMIN = enum.auto()
        ORGANISATION = enum.auto()
        SYSTEM = enum.auto()
        SELF = enum.auto()
        OBJECT = enum.auto() # for everything else

###################################################
# File Object
class FileObject():
    """
    How should a file Object look like?

    """
    id = ""
    path = ""
    fileName = ""
    tags = []
    date = ""
    licenses = []
    certificates = []
    URI = ""
    createdBy = ""
    remote = False

###################################################
# File object content as enum
class FileObjectContent(StrEnumExactlyAsDefined):
    """
    What can be the metadata of a file?
    """
    id = enum.auto()
    path = enum.auto()
    fileName = enum.auto()
    imgPath = enum.auto()
    tags = enum.auto()
    licenses = enum.auto()
    certificates = enum.auto()
    date = enum.auto()
    createdBy = enum.auto()
    createdByID = enum.auto()
    remote = enum.auto()
    size = enum.auto()
    type = enum.auto()
    origin = enum.auto()

###################################################
# File object content as enum
class FileTypes(StrEnumExactlyAsDefined):
    """
    What types are there (see FileObjectContent.type)

    """
    Model = enum.auto()
    File = enum.auto()

###################################################
# Enum for session content
class SessionContent(StrEnumExactlyAsDefined):
    """
    What is saved into the session?

    """
    INITIALIZED = enum.auto()

    NUMBER_OF_LOGIN_ATTEMPTS = enum.auto()
    LAST_LOGIN_ATTEMPT = enum.auto()

    usertype = enum.auto()
    IS_PART_OF_ORGANIZATION = enum.auto()
    PG_PROFILE_CLASS = enum.auto()
    PATH_AFTER_LOGIN = enum.auto()
    MOCKED_LOGIN = enum.auto()
    ORGANIZATION_NAME = enum.auto()
    USER_ROLES = enum.auto()
    USER_PERMISSIONS = enum.auto()
    LOCALE = enum.auto()

###################################################
# Enum for types of users
class ProfileClasses(StrEnumExactlyAsDefined):
    """
    Which classes exist?
    """
    user = enum.auto()
    organization = enum.auto()

###################################################
# Class for default strings
class GlobalDefaults(StrEnumExactlyAsDefined):
    """
    Some things need to be defined globally in name

    """
    anonymous = enum.auto() # default user name for not logged in users

##################################################
# Enum for Events structure
class EventsDescriptionGeneric(StrEnumExactlyAsDefined):
    """
    Websocket events and missed events should be in the same format

    """
    eventType = enum.auto()
    eventID = enum.auto()
    userHashedID = enum.auto()
    eventData = enum.auto()
    orgaEvent = enum.auto()
    triggerEvent = enum.auto()
    primaryID = enum.auto()
    secondaryID = enum.auto()
    reason = enum.auto()
    content = enum.auto()
    createdWhen = enum.auto()