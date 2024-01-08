"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: generate info about environment variables
"""
import os

from django.conf import settings
        
from django.core.management.base import BaseCommand

from django.apps import apps

from code_General.helper.classes import ConfigHelper

####################################################################################
class Command(BaseCommand):
    help = 'generates .env.example file from configured environment variables in apps.py'
    file_intro = ('# This is an example .env file for Semper-KI with following structure:\n'
                  '# ENV_VARNAME=[DEFAULT_VALUE|Nothing] # required? - comment'
                  '\n# first part is for semper-ki internal things (i.e. services which run on internal docker containers)'
                  '\n# and could be used with default values for development,'
                  '\n# second part is for external services you need to fill in :\n')
    current_values = ('# Current values are:\n')

    ##############################################
    def add_arguments(self, parser):
        parser.add_argument('-p','--print',action="store_true", help='Should current parameters be printed?')

    ##############################################
    def handle(self, *args, **options):
        print('Current options:')
        print(str(options))
        s= "POSTGRES_HOST"
        print(f'\n\n{s} -> os says {os.environ.get(s)} and settings says {settings.__getattr__(s)}\n\n')
        semper_ki_cfgs = [app_cfg for app_cfg in apps.get_app_configs() if issubclass(type(app_cfg), ConfigHelper)]
        self.stdout.write (self.file_intro if not options['print'] else self.current_values)
        for app in semper_ki_cfgs:
            env_vars_internal = app.getEnvVarsInternal().items()
            self.stdout.write(f'\n#INTERNAL SERVICES\n\n')
            for key, value in env_vars_internal:
                val = os.environ.get(key,'') if options.get('print') else ( value["default"] if value["default"] else "" )
                #self.stdout.write('{: <30}'.format(f'#{key} -- {value["hint"]} \n') + '{: <100}'.format(f'{key}={val}') + f'# {"required " if value["required"] else ""}')
                self.writeVariable(key,value,val)

            env_vars_external = app.getEnvVarsExternal().items()
            self.stdout.write(f'\n#EXTERNAL SERVICES\n\n')
            for key, value in env_vars_external:
                val = os.environ.get(key,'') if options.get('print') else ( value["default"] if value["default"] else "" )
                #self.stdout.write('{: <30}'.format(f'#{key} -- {value["hint"]} \n') + '{: <100}'.format(f'{key}={val}') + f'# {"required " if value["required"] else ""}')
                self.writeVariable(key,value,val)

    ##############################################
    def writeVariable(self,key,value: dict, val):
        if value.get('type') == 'list' and type(val) != str:
            print(str(type(val)))
            val = ','.join(val)


        self.stdout.write('{: <30}'.format(f'#{key} -- {value["hint"]} \n') + '{: <100}'.format(
            f'{key}={val}') + f'# {"required " if value["required"] else ""}')

