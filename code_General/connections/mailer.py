"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: Writing Mails
"""
import logging

from django.core import mail
from django.conf import settings # THIS ALSO IMPORTS THE NECESSARY SETTINGS FOR EMAIL CONFIGURATION!

loggerDebug = logging.getLogger("django_debug")
loggerError = logging.getLogger("errors")

####################################################################################
class MailingClass():
    """
    later add some other stuff and configuration things as well as perhaps a html template.
    For now just send a mail via default django smtp sendmail
    """

    ####################################################################
    def sendMail(self, to, subject, message):
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

    ####################################################################
    def mailingTemplate(self, subject, language, content):
        """
        Template to use for E-Mail content

        :param subject: Who is it about
        :type subject: str
        :param language: In what language should the mail be send in
        :type language: locale string e.g. de-de, en-gb, ...
        :param content: What this mail is about
        :type content: str
        :return: The Template as string
        :rtype: str

        """
        # TODO
        output = ""
        if "de" in language:
            output = f"An: {subject}\nInformation: {content}\nViele Grüße\nDie Semper-KI"
        elif "en" in language:
            output = f"To: {subject}\nInformation: {content}\nGreetings\nThe Semper-KI"

        return output
