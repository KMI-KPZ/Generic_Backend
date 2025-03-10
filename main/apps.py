"""
Generic Backend

Silvio Weging & Thomas Skodawessely 2023

Contains: Modules that need to be imported

"""
import os, importlib, sys
from django.apps import AppConfig
from django.core.checks import register
from .checks import Tags, checkEnv, checkDb, checkRedis
from logging import getLogger
logger = getLogger("django_debug")

#
#
# # for now coping with configuration things, perhaps could be done better with a custom settings class
# # first all settings from base.py and prod|dev|debug.py are loaded database will be set up
# # then belows AppConfig Child's ready function is called and the environment variables are loaded
# # and the real database connection will be set up
# #
from main.settings.base import ConfigHelper, BackendConfigHelper

#######################################################
class BackendDjangoConfig(AppConfig, BackendConfigHelper):
    """
    Readying the main app
    
    """
    name = 'main' 
    checks_disable = { 'check_env': ('generate_env',), 'check_db' : ('create_db','generate_env'), 'check_redis': ('create_db','generate_env')}

    #######################################################
    def __init__(self,app_name, app_module):
        AppConfig.__init__(self,app_name, app_module)
        BackendConfigHelper.__init__(self)

    #######################################################
    def collectAllImports(self):
        """
        Collect all "imports.py" files and imports content

        """
        currentDirectory = os.getcwd()  # current working directory

        for root, dirs, files in os.walk(currentDirectory):
            if 'imports.py' in files:
                serviceFilePath = os.path.join(root, 'imports.py')

                # create module name by replacing the path separator with dots
                moduleName = os.path.relpath(serviceFilePath, currentDirectory).replace(os.sep, '.').rstrip('.py')

                # import the module
                spec = importlib.util.spec_from_file_location(moduleName, serviceFilePath)
                module = importlib.util.module_from_spec(spec)
                sys.modules[moduleName] = module
                spec.loader.exec_module(module)

                print(f"Imported module {moduleName}")

    #######################################################
    def ready(self):
        """
        Start app

        """
        from django.conf import settings
        self.collectAllImports()

        if self.doCheck('check_env'):
            register(checkEnv, Tags.env_check) # register check_env function with tag env_check
        if self.doCheck('check_db'):
            register(checkDb, Tags.db_check) # register check_db function with tag db_check
        if self.doCheck('check_redis'):
            register(checkRedis, Tags.redis_check)

        super(BackendDjangoConfig, self).ready()

    #######################################################
    def __repr__(self):
        return self.name

    #######################################################
    def doCheck(self, check_name):
        """
        determine if check should be executed
        :param check_name: Name of the check
        :type check_name: str
        :return: True if check should be executed
        :rtype: bool
        """

        import sys
        for tokens in sys.argv:
            if tokens in self.checks_disable[check_name]:
                logger.info(f'check {check_name} will be skipped')
                return False
        logger.info(f'check {check_name} will be executed')
        return True
