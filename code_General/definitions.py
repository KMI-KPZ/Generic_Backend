"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Definitions, Classes, Enums to describe Elements in the Backend as well as Services
"""
import enum

from .utilities.customStrEnum import StrEnumExactlyAsDefined

from .modelFiles.organizationModel import OrganizationDescription
from .modelFiles.userModel import UserDescription

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

###################################################
# Enum for notification settings for users
class NotificationSettingsUser(StrEnumExactlyAsDefined):
    """
    Which notifications can be received?
    Some can be set here but most are specific to the plattform itself (just inherit from this class)
    
    """
    newsletter = enum.auto() 

###################################################
# Enum for notification targets for users
class NotificationTargets(StrEnumExactlyAsDefined):
    """
    What is the target for each notification?
    
    """
    email = enum.auto()	
    event = enum.auto()

###################################################
# Enum for statistics settings for user profiles
class StatisticsForProfiles(StrEnumExactlyAsDefined):
    """
    Which statistics are measured?
    
    """
    lastLogin = enum.auto()
    numberOfLoginsTotal = enum.auto()
    locationOfLastLogin = enum.auto()

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
    notificationSettings = enum.auto()
    priorities = enum.auto()

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
    notifications = enum.auto()
    locale = enum.auto()
    address = enum.auto()
    priorities = enum.auto()
    taxID = enum.auto()

###################################################
# Enum for notification settings for orgas
class NotificationSettingsOrganizations(StrEnumExactlyAsDefined):
    """
    Which notifications can be received?
    Some can be set here but most are specific to the plattform itself
    
    """
    newsletter = enum.auto() 

###################################################
# Enum for priorities for orgas
class PrioritiesForOrganization(StrEnumExactlyAsDefined):
    """
    If the organization has some priorities, they can be set here
    Is used in Semper-KI for calculations, can be used here for whatever
    """
    pass

###################################################
# Class for default strings
class GlobalDefaults(StrEnumExactlyAsDefined):
    """
    Some things need to be defined globally in name

    """
    anonymous = enum.auto() # default user name for not logged in users