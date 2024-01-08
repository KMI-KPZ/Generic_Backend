#!/bin/bash
# This is an entry point override for migrations
echo "SLEEPING FOR 10 SECONDS"
echo "Current ID" $$
sleep 10
pwd

export DJANGO_SETTINGS_MODULE=code_General.settings.production
python manage.py makemigrations
python manage.py migrate

echo "***************************************************************
      Starting Gunicorn
      ***************************************************************"
exec gunicorn --bind 0.0.0.0:8000 code_General.asgi --reload --forwarded-allow-ips="*" --capture-output -k uvicorn.workers.UvicornWorker --workers 16 --threads 16 --timeout 12000