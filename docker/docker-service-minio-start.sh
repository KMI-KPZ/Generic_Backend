#!/bin/sh
echo "Starting Minio with Localstack Environment Variables"
export MINIO_ACCESS_KEY=$LOCALSTACK_ACCESS_KEY
export MINIO_SECRET_KEY=$LOCALSTACK_SECRET
export MINIO_ROOT_USER=$LOCALSTACK_ACCESS_KEY
export MINIO_ROOT_PASSWORD=$LOCALSTACK_SECRET
exec /usr/bin/docker-entrypoint.sh server --console-address ":9001" /data
