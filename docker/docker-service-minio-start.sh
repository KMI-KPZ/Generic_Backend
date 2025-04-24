#!/bin/sh
echo "Starting Minio with Localstack Environment Variables"
#export MINIO_ACCESS_KEY=$S3_LOCAL_ACCESS_KEY
#export MINIO_SECRET_KEY=$S3_LOCAL_SECRET
export MINIO_ROOT_USER=$S3_LOCAL_ACCESS_KEY
export MINIO_ROOT_PASSWORD=$S3_LOCAL_SECRET
exec /usr/bin/docker-entrypoint.sh server --console-address ":9001" /data
