#!/bin/bash
# This is an entry point override for tests
pwd
gunicorn --bind 0.0.0.0:8000 main.asgi --reload --env MODE=production --capture-output --log-level debug -k uvicorn.workers.UvicornWorker --workers 1 --threads 1 --timeout 12000 &
sleep 10
python manage.py test --env production