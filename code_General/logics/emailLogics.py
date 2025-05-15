"""
Generic Backend

Silvio Weging 2024
Lukas Hein 2024

Contains: Logic for Emails
"""
import logging

from ..definitions import *


from django.conf import settings


from ..connections.mailer import MailingClass


from logging import getLogger

logger = logging.getLogger("logToFile")
loggerError = logging.getLogger("errors")

####################################################################################
def logicForSendContactForm(validatedInput):
    try:
        mailer = MailingClass()
        msg = ("Backendsettings: " + settings.BACKEND_SETTINGS +
                "\nName: " +
                validatedInput["name"] +
                "\n" +
                "Email: " +
                validatedInput["email"] + "\n" + "Message: " + validatedInput["message"])
        result = mailer.sendMail(settings.EMAIL_ADDR_SUPPORT, validatedInput["subject"], msg)
        
        return (result, None, 200)
    
    except Exception as e:
        loggerError.error(f"Error in {logicForSendContactForm.__name__}: {e}")
        return (None, e, 500)
