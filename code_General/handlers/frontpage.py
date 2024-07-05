"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Views for some backend websites
"""

from django.http import JsonResponse
from django.shortcuts import render
from django.conf import settings
from logging import getLogger

from rest_framework.decorators import api_view
from drf_spectacular.utils import extend_schema

logger = getLogger("django")


#######################################################
def landingPage(request):
    """
    Landing page for the backend

    :param request: GET request
    :type request: HTTP GET
    :return: Rendered page
    :rtype: HTTPResponse

    """
    return render(
        request,
        "landingPage.html"  # ,
        # context={
        #    "session": request.session.get("user"),
        # "pretty": json.dumps(request.session.get("user"), indent=4),
        # },
    )

#######################################################
def docPage(request):
    """
    Documentation page for the backend

    :param request: GET request
    :type request: HTTP GET
    :return: Rendered page
    :rtype: HTTPResponse

    """
    # response = HttpResponse()
    # construct the file's path
    # url=os.path.join(settings.BASE_DIR,'doc','build','html','index.html')
    # response['Content-Type']=""
    # response['X-Accel-Redirect'] = url
    # return response
    pathOfHtml = request.path.replace('private/doc/', '').replace('index.html', '')
    assert isinstance(pathOfHtml, str), f"In {docPage.__name__}: expected pathOfHtml to be of type string, instead got: {type(pathOfHtml)}"
    logger.info(pathOfHtml)
    if ("_static" in pathOfHtml):
        return render(
            request,
            settings.DOC_DIR + pathOfHtml)
    else:
        return render(
            request,
            settings.DOC_DIR + pathOfHtml + "index.html"
        )
    

#######################################################
def benchyPage(request):
    """
    Landing page for the benchmark tool

    :param request: GET request
    :type request: HTTP GET
    :return: Rendered page
    :rtype: HTTPResponse

    """
    return render(
        request,
        "benchy.html"  # ,
        # context={
        #    "session": request.session.get("user"),
        # "pretty": json.dumps(request.session.get("user"), indent=4),
        # },
    )
