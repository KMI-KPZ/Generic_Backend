"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: Set Settings helper functions
"""


import os, sys
from django.core.management import ManagementUtility

###########################################################
class BackendManagement(ManagementUtility):

    def main_help_text(self, commands_only=False):
        """
        Returns the script's main help text, as a string.

        """
        text = super().main_help_text(commands_only)
        text += '\n\n' + 'SemperKi environment setting: --env production|development|debug|debug_local (default=production):\n'
        text += '  production:  use production settings\n'
        text += '  development: use development settings\n'
        text += '  debug:       use debug settings\n'
        text += '  debug_local: use debug settings with local database\n'
        return text

def set_settings(settingsPath:str):
    """
    Choose correct settings file
    
    :param settingsPath: The path of the settings folder
    :type settingsPath: str
    :return: None
    :rtype: None

    """
    # parse command line arguments 
    import argparse
    base = settingsPath
    default = base + 'production'
    settings = default

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--env', dest='env', nargs='?', type=str, default=None, help='Django settings file to use')
    args = parser.parse_known_args()

    if args[0].env is not None and not args[0].env.startswith('MODE='):
        mode = args[0].env.strip()
        settings = base + mode
        env_file = '.env' + ('.' + mode if mode != 'production' else '')
        env_index = sys.argv.index('--env')
        print('removing --env from sys.argv')
        sys.argv.remove(sys.argv[env_index + 1])
        sys.argv.remove(sys.argv[env_index])
    elif os.environ.get('MODE') is not None:
        print(f'Using environment variable MODE: "{os.environ.get("MODE")}"')
        mode = os.environ.get('MODE').strip()
        settings = base + mode
        env_file = '.env' + ('.' + mode if mode != 'production' else '')
    else:
        settings = default
        env_file = '.env'

    print(f'Settings default settings module to "{settings}" current environment settings are: "{os.environ.get("DJANGO_SETTINGS_MODULE")}"')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings)
    print(
        f'Settings default settings module to "{settings}" current environment settings are: "{os.environ.get("DJANGO_SETTINGS_MODULE")}"')

    print(f'Setting default environment variables file to "{env_file}" from "{os.environ.get("ENV_FILE")}"')
    os.environ.setdefault('ENV_FILE', env_file)
    print(f'Setting default environment variables file to "{env_file}" from "{os.environ.get("ENV_FILE")}"')

    #check if module exists:
    try:
        __import__(settings)
    except ImportError:
        print(f'Could not import settings module {settings}.')
        exit(1)
