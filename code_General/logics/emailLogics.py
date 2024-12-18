"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Logic for Emails
"""
import logging

from ..definitions import *


from django.conf import settings


from ..connections.mailer import MailingClass


from logging import getLogger
logger = getLogger("errors")

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForSendContactForm(validatedInput):
    mailer = MailingClass()
    msg = ("Backendsettings: " + settings.BACKEND_SETTINGS +
            "\nName: " +
            validatedInput["name"] +
            "\n" +
            "Email: " +
            validatedInput["email"] + "\n" + "Message: " + validatedInput["message"])
    result = mailer.sendMail(settings.EMAIL_ADDR_SUPPORT, validatedInput["subject"], msg)
    
    return result
