"""
Generic Backend

Silvio Weging 2024

Contains: Helper functions
"""

from django.conf import settings

##################################################
def filteredEndpointsForAPI(endpoints):
    """
    Filter endpoints if the public api view is desired
   
    """
    if settings.PRODUCTION == True or settings.STAGING == True:
        filtered = []
        for (path, path_regex, method, callback) in endpoints:
            if "api/" in path:
                filtered.append((path, path_regex, method, callback))
        return filtered
    else:
        return endpoints