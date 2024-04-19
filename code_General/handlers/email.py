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
from logging import getLogger

logger = getLogger("django_debug")

#######################################################
@require_http_methods(["POST"])
def sendContactForm(request):
    """
    Send an email from the contact form from the front end

    :param request: HTTP POST request
    :type request: HttpRequest
    :return: JSON to front end having a status and result field with the email count or False
    :rtype: JsonResponse
    """

    # TODO check if logging is necessary
    logger.info(f'received contact form input: "{str(request.body)}')
    data = json.loads(request.body.decode("utf-8"))
    # check if all fields are present
    if not all(key in data for key in ["name", "email", "subject", "message"]):
        return JsonResponse({"status": "error", "result": "missing fields"})

    mailer = MailingClass()
    msg = ("Backendsettings: " + settings.BACKEND_SETTINGS +
           "\nName: " +
           data["name"] +
           "\n" +
           "Email: " +
           data["email"] + "\n" + "Message: " + data["message"])
    result = mailer.sendMail(settings.EMAIL_ADDR_SUPPORT, data["subject"], msg)
    return JsonResponse({"status": "ok", "result": result})
