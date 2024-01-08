#!/bin/sh
exec docker-entrypoint.sh --save 60 1 --loglevel warning --requirepass $REDIS_PASSWORD