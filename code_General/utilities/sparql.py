"""
Part of Semper-KI software

Thomas Skodawessely 2024

Contains: Helper Classes to handle Sparql Queries
"""
from enum import Enum
import re

from django.conf import settings

from SPARQLWrapper import SPARQLWrapper, JSON

from Generic_Backend.code_General.connections.redis import RedisConnection
from Generic_Backend.code_General.utilities.oauth import ManageToken

#######################################################
class QueryType(Enum):
    """
    The type of query

    """
    GET = 1
    INSERT = 2
    UPDATE = 3
    DELETE = 4

#######################################################
class SparqlQueryManager:
    redisCon: RedisConnection
    oauthTokenManager: ManageToken
    endpoint: SPARQLWrapper
    updateEndpoint: SPARQLWrapper

    # derive from this class and create properties like this:
    # myTopic : SparqlResource = {QueryType.GET: "/Ontology/queries/material_Hannes", QueryType.UPDATE: "/Ontology/queries/Data update/Material_Hannes"}
    # can later be accessed like this: myManager.myTopic.getAll() be sure to access only the configured query types

    #######################################################
    def __init__(self, redisConnection, oauthTokenManager, endpoint, updateEndpoint) -> None:
        """

        :param self:
        :param redisConnection: Redis connection object with a connection to the redis server
        :type redisConnection: RedisConnection
        :param oauthTokenManager: the configured oauth token manager to the sparql endpoint
        :type oauthTokenManager: ManageToken
        :param endpoint: the sparql endpoint as URL
        :type endpoint: str

        """

        self.redisCon = redisConnection
        self.oauthTokenManager = oauthTokenManager
        self.endpoint = endpoint
        self.updateEndpoint = updateEndpoint
        self.setup()

    #######################################################
    def setup(self):
        """
        sets up the sparql query manager by loading all queries from the configured class properties containing a dict with keys
        from QueryType and values as path to the query file.
        """

        for query in self.__class__.__dict__.items():
            if isinstance(query[1], dict) and not query[0].startswith("__"):
                self.loadConfig(query[0], query[1])
                # setattr(self, query[0], SparqlQuery(query[1], self.redisCon, self.oauthTokenManager))

    #######################################################
    def loadConfig(self, name, config):
        """
        loads the queries from the config dict and sets them to the sparql resource object
        :param name: name of the property to set
        :type name: str
        :param config: config dict containing the query paths
        :type config: dict

        """

        sparqlResource = SparqlResource(self.endpoint, self.updateEndpoint, self.oauthTokenManager)
        types = [member for member in QueryType]
        for key, path in config.items():
            if key in types:
                sparqlResource.setQuery(key, self.loadQueryFromPath(path))

        setattr(self, name, sparqlResource)

    #######################################################
    def loadQueryFromPath(self, path):
        """
        Load a query from a file path

        :param path: The file path
        :type path: str
        :return: Query content
        :rtype: str
        
        """
        query, exists = self.redisCon.retrieveContentJSON(path)
        if not exists or settings.DEBUG:
            with open(str(settings.BASE_DIR) + path) as queryFile:
                queryFileContent = queryFile.read()
                self.redisCon.addContentJSON(path, {"content": queryFileContent}, True)
                return queryFileContent
        else:
            return query["content"]

    #######################################################
    def sendQuery(self):
        """
        Send query via sparql to endpoint
        
        :return: Query result
        :rtype: JSON

        """
        return self.sparqlQuery.sendQuery()

    #######################################################
    def getResources(self) -> dict:
        """
        Returns resource details

        :return: Dictionary with resources names as key and the resource as value
        :rtype: dict
        
        """
        result =  {}
        for name, resource in self.__dict__.items():
            if isinstance(resource, SparqlResource) and not name.startswith("__"):
                result[name] = resource

        return result


    #######################################################
    def getResourcesAndTypes(self) -> dict:
        """
        Returns resource details and types

        :return: Dictionary with resources names as key and the resource types as array
        :rtype: dict
        
        """
        result = {}
        for name, resource in self.getResources().items():
            result[name] =  []
            for queryType in resource.getSupportedQueryTypes():
                result[name].append(queryType)

        return result

#######################################################
class SparqlResource:
    """
        Contains queries from files and handles access methods to them
    """

    endpoint: SPARQLWrapper = None
    updateEndpoint: SPARQLWrapper = None
    oauthToken: ManageToken = None
    _getQuery: str = None
    _insertQuery: str = None
    _updateQuery: str = None
    _deleteQuery: str = None
    _vars : dict = {}

    #######################################################
    def __init__(self, endpoint: SPARQLWrapper, updateEndpoint: SPARQLWrapper, oauthToken: ManageToken) -> None:
        self.endpoint = endpoint
        self.updateEndpoint = updateEndpoint
        self.oauthToken = oauthToken

    #######################################################
    def setQuery(self, queryType: QueryType, query: str):
        if queryType == QueryType.GET:
            self._getQuery = query
        elif queryType == QueryType.INSERT:
            self._insertQuery = query
        elif queryType == QueryType.UPDATE:
            self._updateQuery = query
        elif queryType == QueryType.DELETE:
            self._deleteQuery = query

        self._vars[queryType] = self.extractVars(query)

    #######################################################
    def _sendQuery(self, query, endpoint=None):
        """
        Send SPARQL query.
        :param self: Contains sparql query as obj
        :type self: Object
        :return: result of query
        :rtype: JSON

        """

        # request a refresh token
        self.oauthToken.checkIfExpired()
        # maybe construct first, save that to redis and then search/filter from that
        endpointCopy = self.endpoint if endpoint is None else endpoint
        endpointCopy.addCustomHttpHeader(
            httpHeaderName="Authorization", httpHeaderValue="Bearer " + self.oauthToken.token["access_token"])
        endpointCopy.setReturnFormat(JSON)
        endpointCopy.setQuery(query)

        try:
            results = endpointCopy.queryAndConvert()
        except Exception as e:
            # print("################## ERROR #################### QUERY:\n" + query + "\n##############################################\n\n" + str(e) + "\n##############################################\n")
            raise e

        if isinstance(results, dict) and "results" in results and "bindings" in results["results"]:
            return results["results"]["bindings"]

        return results

    #######################################################
    def hasGet(self):
        return self._getQuery is not None

    #######################################################
    def hasInsert(self):
        return self._insertQuery is not None

    #######################################################
    def hasUpdate(self):
        return self._updateQuery is not None

    #######################################################
    def hasDelete(self):
        return self._deleteQuery is not None

    #######################################################
    def has(self, queryType: QueryType):
        if queryType == QueryType.GET:
            return self.hasGet()
        elif queryType == QueryType.INSERT:
            return self.hasInsert()
        elif queryType == QueryType.UPDATE:
            return self.hasUpdate()
        elif queryType == QueryType.DELETE:
            return self.hasDelete()

    #######################################################
    def getAll(self):
        if not self.hasGet():
            raise Exception("No get query defined")
        self.endpoint.setMethod("GET")
        self.endpoint.setRequestMethod("GET")
        return self._sendQuery(self._getQuery)

    #######################################################
    def get(self, filter):
        if not self.hasGet():
            raise Exception("No get query defined")
        # TODO insert filter into query
        self.endpoint.setMethod("GET")
        self.endpoint.setRequestMethod("GET")
        return self._sendQuery(self._getQuery)

    #######################################################
    def insert(self, data: dict):
        if not self.hasInsert():
            raise Exception("No insert query defined")
        # check if all vars are in data
        for var in self.getVars(QueryType.INSERT):
            if var not in data:
                raise Exception("Missing data for var: " + var)

        # insert data into query
        query = self._insertQuery
        for key, value in data.items():
            query = query.replace("[$" + key + "]", str(value))
        # query = "query=" + urllib.parse.quote(query)
        self.updateEndpoint.setMethod("POST")
        if settings.DEBUG:
            print("################## INSERT #################### QUERY:\n" + query + "\n##############################################\n")

        return self._sendQuery(query, self.updateEndpoint)

    #######################################################
    def update(self, data, filter=None):
        if not self.hasUpdate():
            raise Exception("No update query defined")
        # TODO insert data into query

        return self._sendQuery(self._updateQuery)

    #######################################################
    def delete(self, filter):
        if not self.hasDelete():
            raise Exception("No delete query defined")
        # TODO insert data into query

        return self._sendQuery(self._deleteQuery)

    #######################################################
    def extractVars(self, query):
        """
        extract all vars (noted as [$VARNAME] in query) from query via regex
        """
        regex = r"\[\$([A-Za-z0-9_]+)\]"
        matches = re.findall(regex, query, re.MULTILINE)
        matches = tuple(set(matches))
        return matches

    #######################################################
    def getVars(self, queryType: QueryType):
        return self._vars.get(queryType, ())

    #######################################################
    def getSupportedQueryTypes(self) -> "list":
        result = []
        for queryType in QueryType:
            if self.has(queryType):
                result.append(queryType.name)
        return result
