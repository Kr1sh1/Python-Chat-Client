from cryptography.fernet import Fernet
import hashlib, os

#An instance of this class is called from another file when data needs to be
#encrypted/decrypted or hashed.
class SecretCrypt():
    def __init__(self, __SecureKey = None):

        #In the constructor we create the key that is used to encrypt and decrypt data.
        #To generate a new key the class must be instanced again.
        #To use an existing key, pass the key as an arguement when calling the class.
        if __SecureKey == None:
            self.__SecureKey = Fernet.generate_key()
            self.__SecureKey = Fernet(self.__SecureKey)
            return
        
        self.__SecureKey = Fernet(__SecureKey)

    #Function to encrypt data with key
    def encrypt(self, message):
        token = self.__SecureKey.encrypt(message.encode("utf-8"))
        return token

    #Function to decrypt data with key
    def decrypt(self, token):
        message = self.__SecureKey.decrypt(token).decode("utf-8")
        return message