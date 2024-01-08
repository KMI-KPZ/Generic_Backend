#!/bin/bash

#check mode for options -m 'local_container' and 'local' (which is default if nothing has been given) other options lead to error

echo "Usage: start_local_dev.sh -m 'local_container' or 'local' local_container starts services and backend in local docker container,
      local starts services and you can run the backend locally via python manage runserver "

while getopts m: option
do
case "${option}"
in
m) MODE=${OPTARG};;
else) echo "Error: Wrong mode. Please use -m 'local_container' or 'local'"
  exit 1;;
esac
done

if [ "$MODE" = "local_container" ]; then
    echo "Starting services and backend in local container"
    docker-compose -p semperki-local-dev -f docker-local-dev-services.yml -f docker-local-dev-container-backend.yml up -d --build backend
    echo "Local containers started"
elif [ "$MODE" = "local" ]; then
    echo "Starting local services, you can use "
    docker-compose -p semperki-local-dev -f docker-local-dev-services.yml up -d
    echo "Local started"
else
    echo "Error: Wrong mode. Please use -m 'local_container' or 'local'"
fi
