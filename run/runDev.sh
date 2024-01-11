#!/bin/bash
# This is an entry point override for migrations
pwd
echo "SLEEPING FOR 10 SECONDS"
sleep 10
export DJANGO_SETTINGS_MODULE=main.settings.development
python manage.py check main
if [ $? -ne 0 ]; then
    echo "DJANGO CHECK FAILED"
    exit 1
fi

python manage.py makemigrations
python manage.py makemigrations main
python manage.py migrate main
python manage.py makemigrations code_SemperKI
python manage.py migrate code_SemperKI
python manage.py migrate
 
exec gunicorn --bind 0.0.0.0:8000 main.asgi --reload --forwarded-allow-ips="*" --env DJANGO_SETTINGS_MODULE=main.settings.development --capture-output  -k uvicorn.workers.UvicornWorker --workers 16 --threads 16 --timeout 12000