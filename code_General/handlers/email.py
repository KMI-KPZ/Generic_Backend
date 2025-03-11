"""
Generic Backend

Thomas Skodawessely 2023

Contains: handlers for sending emails out of different front end forms
"""

import json, logging
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

from ..utilities.basics import ExceptionSerializerGeneric
from ..logics.emailLogics import *

logger = logging.getLogger("django_debug")
loggerError = logging.getLogger("errors")

#########################################################################
# sendContactForm
#"contactForm": ("public/contact/",email.sendContactForm)
#########################################################################
#######################################################
class SReqMail(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    email = serializers.EmailField()
    subject = serializers.CharField(max_length=500)
    message = serializers.CharField(max_length=10000)
#########################################################################
# Handler  
@extend_schema(
    summary="Send an email from the contact form from the front end",
    request=SReqMail,
    tags=['FE - E-Mail'],
    responses={
        200: None,
        400: ExceptionSerializerGeneric,
        500: ExceptionSerializerGeneric
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
        inSerializer = SReqMail(data=request.data)
        if not inSerializer.is_valid():
            message = f"Verification failed in {sendContactForm.cls.__name__}"
            exception = f"Verification failed {inSerializer.errors}"
            loggerError.error(message)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        validatedInput = inSerializer.data
        result, exception, value = logicForSendContactForm(validatedInput)
        
        if exception is not None:
            message = str(exception)
            loggerError.error(exception)
            exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
            if exceptionSerializer.is_valid():
                return Response(exceptionSerializer.data, status=value)
            else:
                return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"status": "ok", "result": result}, status=status.HTTP_200_OK)

    except Exception as error:
        message = f"Error in {sendContactForm.cls.__name__}: {str(error)}"
        exception = str(error)
        loggerError.error(message)
        exceptionSerializer = ExceptionSerializerGeneric(data={"message": message, "exception": exception})
        if exceptionSerializer.is_valid():
            return Response(exceptionSerializer.data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
