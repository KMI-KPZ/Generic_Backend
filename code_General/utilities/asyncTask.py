"""
Part of Semper-KI software

Silvio Weging 2024

Contains: Send away a task in a fire-and-forget fashion
"""

import asyncio

####################################################################
# From https://techoverflow.net/2020/10/01/how-to-fix-python-asyncio-runtimeerror-there-is-no-current-event-loop-in-thread/
def getOrCreateEventLoop() -> asyncio.AbstractEventLoop:
    """
    Since threads don't have their own event loop, a new one must be created usually

    """
    try:
        return asyncio.get_event_loop()
    except RuntimeError as ex:
        if "There is no current event loop in thread" in str(ex):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return asyncio.get_event_loop()

####################################################################
# From https://stackoverflow.com/questions/37278647/fire-and-forget-python-async-await
# DECORATOR
def runInBackground(task):
    """
    Decorator for a task that shall be run in the background when called

    :param task: The function
    :type task: Function Object
    
    """
    def wrapped(*args, **kwargs):
        return getOrCreateEventLoop().run_in_executor(None, task, *args, *kwargs)

    return wrapped

####################################################################
# Example:
@runInBackground
def testTask(a:int,b:str):
    print("Task done", a)
    return str(a)+b
# then use testTask(1," Test") and it will be run async