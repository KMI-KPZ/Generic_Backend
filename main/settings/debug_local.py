"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Further settings for debug mode
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
BACKEND_SETTINGS= "debug_local"

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases


CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://:"+REDIS_PASSWORD+"@host.docker.internal:6379/0",
    }
}