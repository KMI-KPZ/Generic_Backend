# Code Style Guide for the backend of SEMPER-KI
This style guide is more of a "I think this can work" than a hard rule set. Take it with a grain of salt please! There are also some How-To's here, hope it helps.

If you want a good Style Guide for Python, please refer to: [this](https://peps.python.org/pep-0008/).

## Table of content
- [Code Style Guide for the backend of SEMPER-KI](#code-style-guide-for-the-backend-of-semper-ki)
  - [Table of content](#table-of-content)
  - [General](#general)
  - [Folder structure](#folder-structure)
  - [File structure](#file-structure)
  - [Class structure](#class-structure)
  - [Function structure](#function-structure)
  - [Logging](#logging)
    - [Manual logging](#manual-logging)
    - [IP logging](#ip-logging)
  - [Create documentation](#create-documentation)

## General
We use [Camel case](https://en.wikipedia.org/wiki/Camel_case) for almost everything.

## Folder structure
- `backend`: Contains docker files, .env files and files necessary for git.
  - `.vscode`: Contains the settings for the local debug configuration
  - `main`: The main django application
  - `code_*`: Contains source code
    - `handlers`: Files with functions that handle requests from the frontend
    - `migrations`: Rule set for django that defines the content of the database(s). Will be created automatically so no editing!
    - `modelFiles`: Database models
    - `connections`: Capsule classes for handling local and remote connections like ID Management, Database access and much more
    - `settings`: Django settings for this particular application
    - `templates`: html code for some default views, not important
    - `utilities`: Helper files that offer specific functionality for most handlers/services
  - `Benchy`: Benchmark tool for Silvio, can safely be ignored
  - `doc`: Documentation, see [Create Documentation](#create-documentation).
  - `logs`: Log files, see [Logging](#logging)
  - `postgres`: Contains the database(s) for the postgres container
  - `redis`: Contains snapshots of redis

The `code_General` folder is the one with mostly generic code usable by all (future) web-apps.
In the file `main/settings/base.py`, the `INSTALLED_APPS` array must contain the paths of the other apps like `code_General` and those developed by you to be usable in django.

## File structure
Every file should start with a header like this:
```
"""
Part of ... software

<Your Name> <Year>

Contains: ?
"""
```

Followed by all the imports. The order of those should be:
python, django, packages, local files of the backend, logger
Where local files of that module are imported via `.` and those of other module via `<modulename>.`. Imports must be hierarchical! That means imports from files inside `code_General` are allowed but no stuff from deriving code into `code_General`. This avoids spaghetti code.
```
import json, logging
from django.conf import settings

from channels.layers import get_channel_layer

from ..utilities import basics

from code_General.connections import redis

logger = logging.getLogger("logToFile")
################################################################################################
```
The last line of pound signs represents a visual cut. These are also used above every function or class, like this:
```
#######################################################
@require_http_methods(["GET"])
def createOrderCollectionID(request):
    ...

#######################################################
@require_http_methods(["PATCH"])
def updateOrderCollection(request):
    ...
``` 

It is recommended to place functions which are used inside the same file as helper functions at the top of the file. Then functions which use GET, followed by those who PATCH, PUT or POST and at the end those that DELETE. If these are inside a class then this structure recursively aplies to member functions as well.


## Class structure
Since object oriented programming is not enforced in python, classes usually serve the purpose of namespaces or to encapsulate semantically related (static) functions. Nevertheless, the structure is the same as in C++ or Java:
```
#######################################################
class ManageQueries():
    """
    Contains query from file as object

    """
    savedQuery = None

    #######################################################
    def __init__(self, ...):
        ...

    #######################################################
    def sendQuery(self):
        ...
```
The brackets after the class names are optional if there is no inheritance. 

Since this backend uses docstring, a comment block containing some context is necessary. This is followed by the member variables, each with an initial value. After that, an `__init__` function is used to do some stuff when the class is initialized. 

Every member function needs `self` as parameter from which member variables and functions can be called. If a function is static, the decorator `@staticmethod` is used and `self` is not a valid parameter anymore. Classes that are used as namespaces withouth member variables (so called static classes) only contain such functions since there won't be any instance of the class ever.

Exceptions to this structure are Enum-Classes:
```
####################################################################################
# Enum for updateOrder
class EnumUpdates(enum.Enum):
    status = 1
    chat = 2
    files = 3
    service = 4
    contractor = 5
    details = 6
```

## Function structure
Functions usually contain the visual barrier, some decorators that check parameters before the function is called, the definition of the function and the docstring followed by the function logic.
```
#######################################################
@checkIfUserIsLoggedIn(json=True)
@require_http_methods(["GET"])
@checkIfRightsAreSufficient(json=True)
def getMissedEvents(request):
    """
    Show how many events (chat messages ...) were missed since last login.

    :param request: GET Request
    :type request: HTTP GET
    :return: JSON Response with numbers for every order and orderCollection
    :rtype: JSON Response

    """
    ...
```
If the type of a parameter and or the return type of the function is important, it can be given like this:
```
def foo(param:type) -> retType:
    ...
```
The docstring is structures as follows:
```
"""
Context
(newline)
:param firstParam: Description
:type firstParam: int, str, dict, ...
:param secondParam: Description
:type secondParam: int, str, dict, ....
...
:return: Description
:rtype: Return type of function, can be multiple things like None|Exception|int
"""
```

Needless to say, every return path must be implemented and the number of return types should be kept to a minimum. 

As for the logic of the function, every function that could throw an exception should be guarded by `try` and `except`:
```
    ##############################################
    @staticmethod
    def getOrderObj(orderID):
        """
        Get one order.

        :param orderID: order ID for an order
        :type orderID: str
        :return: Requested order
        :rtype: Order

        """
        try:
            currentOrder = Orders.objects.get(orderID=orderID)
            return currentOrder
        except (ObjectDoesNotExist) as error:
            return None
        except (Exception) as error:
            print(error)
        
        return None
```
If the return value type is checked, the exception can even be returned and handled:
```
##############################################
def foo():
    """
    ...
    """
    try:
        ...something...
    except (Exception) as error:
        print(error)
        return error

##############################################
def otherFoo(request):
    """
    ...
    """
    try:
        returnVal = foo()
        if isinstance(returnVal, Exception):
            raise returnVal
        return HttpResponse("Success",status=200)
    except (Exception) as error:
        return HttpResponse("Failed",status=500)
```

Tip: Since Python is interpreted, not compiled, accessing the database twice for the same data is frowned upon. Try to write the code so that information is stored in variables if you need them again. Also: nothing is really saved between the requests (if you don't store it in the session that is) so try to write the code with this in mind. 

## Logging
### Manual logging
Log files are necessary to keep track of what's happending when. Docker logs container output automatically, but it is neither structured, nor very readable. Therefore I came up with a structured log file in csv format that can be opened and searched (it should also help with legal stuff). The log file which contains manually written logs is called `info.log` in the `logs` folder. In order for this to function, the docker container needs write permissions, so set the user to 5678 with chown.

Writing to this log file in the code needs some preliminaries:
- The logging configuration lies in the settings->base.py file and is saved into `LOGGING`
- The handler for file logging is called `file` and is associated with the `logToFile` logger
- Every file should import the logging and the logger like this:
  ```
  import logging
  from datetime import datetime
  from ..utilities.basics import Logging
  logger = logging.getLogger("logToFile")
  ```
- Then in any function the logger can be called with `logger.info(...)` where ... is a string with a certain structure
- The structure is as follows: Subject,description,Predicate,description,Object,description,date
- For this I implemented some Enum-classes in the basics utility file: Subject,Predicate,Object
- They contain some generic elements to make searching/sorting the file easier. If the generics don't suffice, .SUBJECT, .PREDICATE, and .OBJECT can be used respectively.
- Example:
  ```
  logger.info(f"{Logging.Subject.USER},{pgProfiles.ProfileManagementBase.getUser(request.session)['name']},{Logging.Predicate.EDITED},updated,{Logging.Object.OBJECT},order {orderCollectionID}," + str(datetime.now()))

  ```
  which leads to the following line in the logfile:
  ```
  user,silvio,edited,updated,object,order dadfg124tk#321,2023-09-20 11:47:58.136877
  ```

### IP logging
If a person (most likely some bad guy) tries to access a backend path that does not exist, its IP is logged into the `ip_log.log` file for later repercussions like banning the ip or something. The implementation of this can be found in the `statistics.py` handler and the `urls.py` file via `urlpatterns.append(re_path(r'^.*', statistics.getIpAdress, name="everythingElse"))`.

## Create documentation
Docs are automatically created via [sphinx](https://www.sphinx-doc.org/en/master/). This means you need to have sphinx and sphinx-autoapi installed via pip. The doc is generated by opening a terminal/powershell, going into the backend->doc folder and using `sphinx-build -b html source/ build/html` as a command. It can be accessed either by opening the `index.html` or by running the backend and calling `127.0.0.1:8000/private/doc/`.
