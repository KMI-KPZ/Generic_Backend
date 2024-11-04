"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: Writing Mails
"""
import logging
from django.core import mail
from django.conf import settings # THIS ALSO IMPORTS THE NECESSARY SETTINGS FOR EMAIL CONFIGURATION!
from django.template.loader import render_to_string
from django.utils.translation import gettext as _
import os

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
                [to],
                html_message=message,  # Use the HTML message
                fail_silently=False,
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
        :return: The Template as HTML string
        :rtype: str
        """
        context = {
            'subject': subject,
            'language': language[:2],
            'content': content,
            'greeting': _('Hello,') if 'en' in language else _('Hallo,'),
            'closing': _('Best regards,') if 'en' in language else _('Viele Grüße,'),
            'signature': _('The Semper-KI Team') if 'en' in language else _('Das Semper-KI Team'),
            'visit_website': _('Visit our website') if 'en' in language else _('Besuchen Sie unsere Website'),
            'rights': _('All rights reserved') if 'en' in language else _('Alle Rechte vorbehalten')
        }
        return render_to_string('email_template.html', context)