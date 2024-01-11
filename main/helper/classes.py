"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: Services for database calls
""" 

from django.core.checks import Error, Info
import os
import logging

logger = logging.getLogger("django_debug")

####################################################################################
class ConfigHelper:
    """
    Helping with config stuff

    """
    env_vars = {}
    env_vars_internal = {}
    env_vars_external = {}

    dbs = ()

    ##############################################
    def __init__(self):
        self.env_vars = dict(self.env_vars_internal, **self.env_vars_external)

    ##############################################
    def getEnvVars(self):
        return self.env_vars

    ##############################################
    def getEnvVarsInternal(self):
        return self.env_vars_internal

    ##############################################
    def getEnvVarsExternal(self):
        return self.env_vars_external

    ##############################################
    def checkEnvVars(self):
        remarks = []
        for env_name, env_value in self.getEnvVars().items():
            # parameter not given - no default value - required
            if (env_name not in os.environ
                    and env_value.get('required',None) is True
                    and env_value['default'] is None):
                remarks.append(Error(f'missing environment variable "{env_name}"',
                                     hint=env_value[
                                              'hint'] + "\n" + f' Check your {os.environ.get("ENV_FILE",".env")} file '
                                     , id='env_check'))
            # parameter not given - default value - required
            elif (env_name not in os.environ and env_value.get('required',None) is True
                  and env_value['default'] is not None):
                remarks.append(Info(f'omitted environment variable "{env_name}"',
                                       hint= env_value[
                                                'hint'] + f' chosen default value: "{str(env_value["default"])}"' + "\n" + f'Check your {os.environ.get("ENV_FILE",".env")} file ',
                                       id='env_check'))
        return remarks

    ##############################################
    def loadEnvVars(self, target_module):
        for env_name in self.env_vars:
            if self.env_vars[env_name].get('type',None) == 'list':
                setattr(target_module,self.env_vars[env_name]['var'],
                        os.environ.get(env_name, self.env_vars[env_name]['default']).split(','))
            elif self.env_vars[env_name].get('type',None) == 'bool':
                setattr(target_module,self.env_vars[env_name]['var'],
                        os.environ.get(env_name, self.env_vars[env_name]['default']) == 'True')
            else:
                setattr(target_module,self.env_vars[env_name]['var'],
                                 os.environ.get(env_name, self.env_vars[env_name]['default']))

    ##############################################
    def getDbAliases(self) -> tuple:
        return self.dbs

    ##############################################
    def doCheck(self) -> bool:
        return True
