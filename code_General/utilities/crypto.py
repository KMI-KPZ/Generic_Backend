"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for cryptographics
"""
import secrets, hashlib, xxhash, base64
from io import BytesIO
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
import psutil
#version needed in requirements

#######################################################
def generateMD5(someString) -> str:
    """
    Convert string to md5 hashed string

    :param someString: String that shall be hashed
    :type someString: string
    :return: string containing the md5 hash
    :rtype: string

    """
    return hashlib.md5(someString.encode()).hexdigest()

#######################################################
def generateSecureID(someString) -> str:
    """
    Convert string to as secure as possible hashed string

    :param someString: String that shall be hashed
    :type someString: string
    :return: string containing the hash
    :rtype: string

    """
    return hashlib.sha512(someString.encode()).hexdigest()

#######################################################
def generateSalt(size = 5) -> str:
    """
    Generate unique random salt string to be attached to another string before hashing

    :param size: Number of characters generated as salt
    :type size: int
    :return: string containing salt
    :rtype: string

    """
    return secrets.token_hex(size)


#######################################################
def generateNoncryptographicHash(someString) -> str:
    """
    Convert string to hashed string

    :param someString: String that shall be hashed
    :type someString: string
    :return: string containing the hash
    :rtype: string

    """
    return xxhash.xxh128_hexdigest(someString.encode())

#######################################################
def generateURLFriendlyRandomString() -> str:
    """
    Generate random string

    :return: random string
    :rtype: string

    """
    return secrets.token_urlsafe(32)

#######################################################
def generateAESKey() -> str:
    """
    Generate a one time use AES Key

    :return: Key to be saved somewhere
    :rtype: string
    
    """

    return base64.b64encode(get_random_bytes(32)).decode('utf-8')

#######################################################
def encryptAES(key:str, file:BytesIO) -> BytesIO:
    """
    Encrypt a file with a previously set key

    :param key: String containing the encryption key
    :type key: str
    :param file: The file to be encrypted
    :type file: BytesIO or inMemoryFile
    :return: Encrypted file
    :rtype: BytesIO

    """

    cipher = AES.new(base64.b64decode(key), AES.MODE_CFB)
    contentOfFile = file.read()
    encryptedContentOfFile = cipher.encrypt(contentOfFile)
    outFile = BytesIO()
    outFile.write(cipher.iv)
    outFile.write(encryptedContentOfFile)
    outFile.seek(0)
    
    return outFile

#######################################################
def decryptAES(key:str, file:BytesIO) -> BytesIO:
    """
    Decrypt a file with a previously set key

    :param key: String containing the encryption key
    :type key: str
    :param file: The file to be decrypted
    :type file: BytesIO or inMemoryFile
    :return: Decrypted file
    :rtype: BytesIO

    """

    iv = file.read(16)
    restOfFile = file.read()
    cipher = AES.new(base64.b64decode(key), AES.MODE_CFB, iv=iv)
    decryptedFile = cipher.decrypt(restOfFile)

    return BytesIO(decryptedFile)

#######################################################

class EncryptionAdapter:
    pass


class EncryptionAdapter():
    """
    Adapter class for encryption and decryption of file like objects
    usage:
        create an instance of this class with a filelike object or stream which has a read method
        call setupDecryptOnRead with a key to decrypt the file while you are reading from it
        call setupEncryptOnRead with a key to encrypt the file while you are reading from it

        if en/de-cryption is set up you can read from the filelike object and it will be encrypted/decrypted on the fly
        while encrypting the iv is sent first and then the encrypted file content
        while decrypting the iv is read from the file and then the file content is decrypted on the fly and returned (without the iv)
    """

    iv = None
    cipher = None
    inputFile = None
    doDecrypt = False
    doEncrypt = False
    readBlocks = 0
    bytesSent = 0
    key = None
    debugLogger = None

    def __init__(self, inputFile):
        """

        :param inputFile: The filelike object to be encrypted/decrypted or - only read
        :type inputFile: filelike (must have a read method)
        :param doDebug: If set to True the adapter will print debug information
        :type doDebug: bool
        """
        self.inputFile = inputFile

        super().__init__()


    ##############################################
    def setupDecryptOnRead(self, key: str):
        """
        Set up the adapter to decrypt the file while reading from it | obviously encrypting is disabled

        :param key: The key to use for decryption
        :type key: str
        """

        if hasattr(self.inputFile,'seek'):
            try:
                self.inputFile.seek(0)
            except:
                pass

        self.key = key
        self.iv = self.inputFile.read(16)
        self.cipher = AES.new(key, AES.MODE_CFB, iv=self.iv)
        self.doDecrypt = True
        self.doEncrypt = False


    ##############################################
    def setupEncryptOnRead(self, key: str):
        """
        Set up the adapter to encrypt the file while reading from it | obviously decrypting is disabled

        :param key: The key to use for encryption
        :type key: str
        """

        self.iv = get_random_bytes(16)
        self.cipher = AES.new(key, AES.MODE_CFB, iv=self.iv)
        self.doEncrypt = True
        self.doDecrypt = False


    ##############################################
    def read(self, size=-1):
        """
        Read from the filelike object and encrypt/decrypt the content on the fly (or do nothing)

        :param size: The amount of (net) bytes to read
        :type size: int
        :return: the bytes read from the filelike object
        :rtype: bytes | bytearray

        """
        self._logMemInfo(f"Read counter: {self.readBlocks} - current block shall be of size {size / 1024 / 1024} MB ")
        self.readBlocks += 1

        if self.doDecrypt:
            return self.cipher.decrypt(self.inputFile.read(size))
        elif self.doEncrypt:
            if size == -1:
                return self.iv + self.cipher.encrypt(self.inputFile.read())
            elif self.bytesSent < 16:
                sizeForIV = min(16 - self.bytesSent, size)
                toSend = self.iv[self.bytesSent: self.bytesSent + sizeForIV] + (self.cipher.encrypt(self.inputFile.read(size - sizeForIV)) if size - sizeForIV > 0 else b'')
                self.bytesSent += size
                self._logMemInfo(f'Sending with IV: {toSend[0:16]}')
                return toSend
            else:
                self.bytesSent += size
                toSend = self.cipher.encrypt(self.inputFile.read(size))
                print(f'Sending without IV: {toSend[0:16]}')
                return toSend
        else:
            return self.inputFile.read(size)


    ##############################################
    def reset(self) -> bool:
        """
        Reset the filelike object to the beginning

        """

        if not hasattr(self.inputFile,'seek'):
            return False

        self.readBlocks = 0
        if self.doDecrypt:
            self.inputFile.seek(16)
            self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        elif self.doEncrypt:
            self.inputFile.seek(0)
            self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        else:
            self.inputFile.seek(0)
        return True

    def setDebugLogger(self, logger) -> EncryptionAdapter:
        """
        Set the debug logger for the adapter

        :param logger: The logger to use
        :type logger: Logger
        """
        self.debugLogger = logger
        return self

    ##############################################
    def _logMemInfo(self,comment=""):
        """
        Print memory info with a comment to the debug logger if it is set

        :param comment: The comment to print
        :type comment: str

        """
        if not self.debugLogger:
            return

        self.debugLogger.debug(f'Current memory usage: {psutil.Process().memory_info().rss / 1024 / 1024} MB | {comment}')