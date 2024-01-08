"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: Writing Mails
"""
import logging

from django.core import mail
from django.conf import settings

loggerDebug = logging.getLogger("django_debug")
loggerError = logging.getLogger("errors")

####################################################################################
class KissMailer():
    """
    later add some other stuff and configuration things as well as perhaps a html template.
    For now just send a mail via default django smtp sendmail
    """

    def sendmail(self, to, subject, message):
        """
        Send a mail

        :param self: mailer object
        :type self: KissMailer
        :param to: recipient email address (1 only)
        :type to: str
        :param subject: subject of the mail
        :type subject: str
        :param message: message of the mail
        :type message: str
        :return: number of sent emails or False on failure
        :rtype: int or bool
        """

        loggerDebug.debug(f'creating mail to {to} with subject {subject} and message {message}')
        try:
            connection = mail.get_connection()
            email = mail.send_mail(
                subject,
                message,
                settings.EMAIL_ADDR_SUPPORT,
                [to], False,
                connection=connection)
            return email
        except Exception as e:
            loggerError.error(f'error sending mail: {e}')
            return False
