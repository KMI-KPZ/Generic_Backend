"""
Generic Backend

Thomas Skodawessely 2023

Contains: Manual creation of db
"""

import logging

from django.core.management.base import BaseCommand

logger = logging.getLogger("django_debug")

####################################################################################
class Command(BaseCommand):
    help = 'creates database from configured environment variables in apps.py if not exists'

    def handle(self, *args, **options):
        #check if db exists
        from django.conf import settings
        import psycopg2
        connection = None
        try:
            connection = psycopg2.connect(user = settings.DATABASES['default']['USER'],
                                          password = settings.DATABASES['default']['PASSWORD'],
                                          host = settings.DATABASES['default']['HOST'],
                                          port = settings.DATABASES['default']['PORT'],
                                          database = 'postgres')
        except:
            logger.error(f"Error while connecting to PostgreSQL with user {settings.DATABASES['default']['USER']} on host {settings.DATABASES['default']['HOST']} with port {settings.DATABASES['default']['PORT']} and database postgres")
            exit(1)

        connection.autocommit = True
        cur = connection.cursor()
        cur.execute("SELECT datname FROM pg_database;")
        logger.info(f'checking if database "{settings.DATABASES["default"]["NAME"]}" exists')
        rows = cur.fetchall()
        db_exists = False
        for row in rows:
            if row[0] == settings.DATABASES['default']['NAME']:
                db_exists = True
                logger.info(f'Database {settings.DATABASES["default"]["NAME"]} already exists')
                exit(0)
                break
        logger.info(f'Database {settings.DATABASES["default"]["NAME"]} does not exist')
        if not db_exists:
            try:
                cur = connection.cursor()
                cur.execute(f'CREATE DATABASE {settings.DATABASES["default"]["NAME"]};')
                logger.info(f"Database {settings.DATABASES['default']['NAME']} created successfully")
                exit(0)
            except (Exception, psycopg2.DatabaseError) as error:
                #print error
                logger.error(f"Error while creating database {settings.DATABASES['default']['NAME']} : {str(error)}")
                exit(1)


