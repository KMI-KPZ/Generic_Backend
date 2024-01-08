"""
ASGI config for code_General project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""

import os
# from django.core.asgi import get_asgi_application
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'code_General.settings')
# application = get_asgi_application()


from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.sessions import SessionMiddlewareStack

from .settings import set_settings

set_settings()

django_asgi_app = get_asgi_application()

from .urls import websockets
#os.environ.setdefault("DJANGO_SETTINGS_MODULE", "code_General.settings.base")

os.environ.setdefault('SERVER_GATEWAY_INTERFACE', 'asgi')

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "https": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(SessionMiddlewareStack(URLRouter(websockets))),
    }
)