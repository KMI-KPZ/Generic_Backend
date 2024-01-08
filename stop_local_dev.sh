#!/bin/bash
docker-compose --env_file .env.local_container -f docker-local-dev-services.yml -f docker-local-dev-container-backend.yml down