"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for using the key-value store in redis
"""
import logging

import redis, json, pickle
from django.conf import settings

logger = logging.getLogger("errors")

####################################################################################
class RedisConnection():

    redis_instance = ""

    def __init__(self) -> None:
        logger.debug(f"USING REDIS PASSWORD: {settings.REDIS_PASSWORD}")
        self.redis_instance = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=0, password=settings.REDIS_PASSWORD)

    #######################################################
    def addContent(self, key, content, expire=False):
        """
        Save a key and its content in redis.

        :param key: key, usually a session ID
        :type key: String
        :param content: The stuff that should be saved
        :type content: Differs, will be set to binary here
        :return: Either "true" if it worked or an error if not
        :rtype: Bool

        """

        try:
            self.redis_instance.set(key, pickle.dumps(content))
            if expire:
                self.redis_instance.expire(key, 86400) # 24 hours until deletion of the data
            return True
        except (Exception) as error:
            logger.error(f'could not add content to redis: {str(error)}')
            return error
        
    #######################################################
    def addContentJSON(self, key, content, expire=False):
        """
        Save a key and its content in redis.

        :param key: key, usually a session ID
        :type key: String
        :param content: The stuff that should be saved
        :type content: Differs, will be set to binary here
        :return: Either "true" if it worked or an error if not
        :rtype: Bool

        """

        try:
            self.redis_instance.set(key, json.dumps(content))
            if expire:
                self.redis_instance.expire(key, 86400) # 24 hours until deletion of the file
            return True
        except (Exception) as error:
            logger.error(f'could not add content to redis: {str(error)}')
            return error

    #######################################################
    def deleteKey(self, key):
        """
        Delete key and value from redis by key.

        :param key: key, usually a session ID
        :type key: String
        :return: Flag to show if it worked or not
        :rtype: Bool

        """
        try:
            self.redis_instance.delete(key)
        except (Exception) as error:
            logger.error(f'could not delete key from redis: {str(error)}')
            return False
        return True

    #######################################################
    def retrieveContent(self, key, deleteOrNot=False):
        """
        Retrieve content from redis by key.
        WARNING: This is not secure! It would be better to use JSON

        :param key: key, usually a session ID
        :type key: String
        :param deleteOrNot: Decides if the key:content pair should be deleted after retrieval
        :type deleteOrNot: Bool
        :return: content
        :rtype: Differs, not binary

        """
        try:
            retrievedContent = self.redis_instance.get(key)
            if retrievedContent is not None:
                content = pickle.loads(retrievedContent)
            else:
                return ("", False)
        except (Exception) as error:
            logger.error(f'could not retrieve content from redis: {str(error)}')
            return (error, False)

        if deleteOrNot == True:
            self.redis_instance.delete(key)

        return (content, True)

    #######################################################
    def retrieveContentJSON(self, key, deleteOrNot=False):
        """
        Retrieve content from redis by key.

        :param key: key, usually a session ID
        :type key: String
        :param deleteOrNot: Decides if the key:content pair should be deleted after retrieval
        :type deleteOrNot: Bool
        :return: content
        :rtype: Differs, not binary

        """
        try:
            retrievedContent = self.redis_instance.get(key)
            if retrievedContent is not None:
                content = json.loads(retrievedContent)
            else:
                return ("", False)
        except (Exception) as error:
            logger.error(f'could not retrieve content from redis: {str(error)}')
            return (error, False)

        if deleteOrNot == True:
            self.redis_instance.delete(key)

        return (content, True)

