"""
Generic Backend

Thomas Skodawessely 2023

Contains: File upload helpers
"""

import os
from io import BytesIO

from django.http import FileResponse
from ..connections import s3
from ..definitions import FileObjectContent

#######################################################
def deleteFileHelper(fileContent: dict) -> None:
    """
    Deletes the file from either the remote or the local storage if so desired and flagged

    :param fileContent: the file content object
    :type fileContent: dict
    :return: None
    :rtype: None
    
    """
    if FileObjectContent.deleteFromStorage not in fileContent or fileContent[FileObjectContent.deleteFromStorage]:
        if FileObjectContent.isFile not in fileContent or fileContent[FileObjectContent.isFile]:
            if fileContent[FileObjectContent.remote]:
                s3.manageRemoteS3.deleteFile(fileContent[FileObjectContent.path])
            else:
                s3.manageLocalS3.deleteFile(fileContent[FileObjectContent.path])

#######################################################
def syncBytesioIterator(bytesio: BytesIO, chunk_size: int = 8192):
    """
    Synchronous iterator for bytesio

    :param bytesio: a byte buffer object of what ever you want to stream (e.g. a file)
    :type bytesio: BytesIO
    :param chunk_size: size of iterator chunks
    :type chunk_size: int
    :return: sync iterator
    :rtype: iterator

    """

    while True:
        chunk = bytesio.read(chunk_size)
        if not chunk:
            break
        yield chunk

#######################################################
async def asyncBytesioIterator(bytesio: BytesIO, chunk_size: int = 8192):
    """
    Asynchronous iterator for bytesio

    :param bytesio: a byte buffer object of what ever you want to stream  (e.g. a file)
    :type bytesio: BytesIO
    :param chunk_size: sie of iterator chunks
    :type chunk_size: int
    :return: async iterator
    :rtype: iterator

    """

    while True:
        chunk = bytesio.read(chunk_size)
        if not chunk:
            break
        yield chunk

#######################################################
def createFileResponse(bytesio: BytesIO, filename: str) -> FileResponse:
    """
    Create a file response for a given file and sync/async context

    :param bytesio: a file like object in BytesIO format
    :type bytesio: BytesIO
    :param filename: name of the file
    :type filename: str
    :return: an FileResponse object with according async or sync iterator over the given bytesio object
    :rtype: FileResponse

    """

    if os.environ.get("SERVER_GATEWAY_INTERFACE", 'wsgi') == 'asgi':
        # async context
        return FileResponse(asyncBytesioIterator(bytesio), as_attachment=True, filename=filename)
    else:
        # sync context
        return FileResponse(syncBytesioIterator(bytesio), as_attachment=True, filename=filename)
