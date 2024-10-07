"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Decorators and functions that check if the api call is legit and such
"""

from functools import wraps

from django.http import HttpResponse, JsonResponse

from ..connections.postgresql.pgAPIToken import checkAPIToken


######### DECORATOR ##############################
def checkIfAPICallIsLegitimate():
    """
    Check whether the current user has a legit API token

    :return: Response whether the authentification token in the call was legit. If so, call the function.
    :rtype: HTTPRespone/JSONResponse, Func
    """

    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if "HTTP_AUTHORIZATION" in request.META:
                token = request.META["HTTP_AUTHORIZATION"]
                if checkAPIToken(token):
                    return func(request, *args, **kwargs)
                else:
                    return HttpResponse("API token invalid!", status=401)
            else:
                return HttpResponse("No Authorization token in header!", status=401)
            
        return inner

    return decorator