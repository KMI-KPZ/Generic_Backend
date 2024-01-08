"""
Part of Semper-KI software

Silvio Weging 2023

Contains: Services for cryptographics
"""
import secrets, hashlib, xxhash, base64
from io import BytesIO
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

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
