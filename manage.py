#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
from code_General.settings import BackendManagement, set_settings
import sys



def main():
    #"""Run administrative tasks."""
    #os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'code_General.settings.development')
    #print("SETTING FILE USED: " + os.environ['DJANGO_SETTINGS_MODULE'], flush=True)

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    set_settings()

    utility = BackendManagement(sys.argv)
    utility.execute() 

if __name__ == '__main__':
    main()
