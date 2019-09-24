# pylint: disable=W0601,W0201,C
import rsa, multiprocessing
number_of_cpu_cores = multiprocessing.cpu_count()

#An instance of this class is called from another file when data needs to be
#encrypted, decrypted or have the public key retrieved.
class RSACrypt():
    def __init__(self):
        (self.__public_key , self.__private_key) = rsa.newkeys(4096, poolsize=number_of_cpu_cores)

    def get_public_key(self):
        return self.__public_key
    def encrypt_message(self, message, pub_key):
        message_bytes = message.encode("utf8")
        encrypt_message = rsa.encrypt(message_bytes, pub_key)
        return encrypt_message

    def decrypt_message(self, encrypt_message):
        decrypt_message_bytes = rsa.decrypt(encrypt_message, self.__private_key)
        decrypt_message = decrypt_message_bytes.decode("utf8")
        return decrypt_message

if __name__ == "__main__":
    RSAClass = RSACrypt()
    public_key = RSAClass.get_public_key()
    encrypted_message = RSAClass.encrypt_message("This is my message", public_key)
    print(encrypted_message)
    decrypted_message = RSAClass.decrypt_message(encrypted_message)
    print(decrypted_message)