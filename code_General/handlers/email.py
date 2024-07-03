"""
Part of Semper-KI software

Thomas Skodawessely 2023

Contains: handlers for sending emails out of different front end forms
"""

import json
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from ..connections.mailer import MailingClass
from django.conf import settings

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema

from ..utilities.basics import ExceptionSerializer

from logging import getLogger

logger = getLogger("django_debug")

#########################################################################
# sendContactForm
#"contactForm": ("public/contact/",email.sendContactForm)
#########################################################################
#TODO Add serializer for sendContactForm
#########################################################################
# Handler  
@extend_schema(
    summary="Send an email from the contact form from the front end",
    request=None,
    tags=['email'],
    responses={
        200: None,
        400: ExceptionSerializer,
        500: ExceptionSerializer
    },
)
@api_view(["POST"])
def sendContactForm(request:Request):
    """
    Send an email from the contact form from the front end

    :param request: HTTP POST request
    :type request: HttpRequest
    :return: JSON to front end having a status and result field with the email count or False
    :rtype: JsonResponse
    """

    try:
        # TODO check if logging is necessary
        logger.info(f'received contact form input: "{str(request.body)}')
        data = json.loads(request.body.decode("utf-8"))
        # check if all fields are present
        if not all(key in data for key in ["name", "email", "subject", "message"]):
            return Response({"status": "error", "result": "missing fields"}, status=status.HTTP_400_BAD_REQUEST)

        mailer = MailingClass()
        msg = ("Backendsettings: " + settings.BACKEND_SETTINGS +
               "\nName: " +
               data["name"] +
               "\n" +
               "Email: " +
               data["email"] + "\n" + "Message: " + data["message"])
        result = mailer.sendMail(settings.EMAIL_ADDR_SUPPORT, data["subject"], msg)
        return Response({"status": "ok", "result": result}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f'error sending contact form: {e}')
        return Response({"status": "error", "result": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
