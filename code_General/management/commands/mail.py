"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: 
"""

from django.core.management.base import BaseCommand
from code_General.connections.mailer import KissMailer
from logging import getLogger
logging = getLogger("django_debug")

####################################################################################
class Command(BaseCommand):
    """
    Sends a test mail to see if config is correct
    
    """
    help = 'sends a test mail to see if config is correct'

    ##############################################
    def add_arguments(self, parser):
        """
        :param self: Command object
        :type self: Command
        :param parser: parser object
        :type parser: ArgumentParser
        :return: None
        :rtype: None
        """
        parser.add_argument('to', type=str, help='the mail address to send the test mail to')

    ##############################################
    def handle(self, *args, **options):
        """
        :param self: Command object
        :type self: Command
        :param args: arguments
        :type args: list
        :param options: options
        :type options: dict
        :return: None
        :rtype: None
        """

        mailer = KissMailer()
        logging.info(f'sending test mail to {options["to"]}')
        mailer.sendmail(options['to'], 'test mail', 'this is a test mail')



