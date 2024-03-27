class EncryptionAdapter:
    """
    Class that encapsulates multiple framework, algorithm pairs for ease of use
    """
    def __init__(self, encryption_library):
        """
        Constructor
        :param encryption_library: class that quacks like a framework
        """
        self.encryption_library = encryption_library

    def encrypt(self, plaintext, key, algorithm):
        return self._get_encryptor(algorithm)(plaintext, key)

    def decrypt(self, ciphertext, key, algorithm):
        return self._get_decryptor(algorithm)(ciphertext, key)

    def _get_encryptor(self, algorithm):
        encryptors = {
            'AES': self.encryption_library.encrypt_aes,
            'DES': self.encryption_library.encrypt_des,
            'RSA': self.encryption_library.encrypt_rsa,
            'BF': self.encryption_library.encrypt_blowfish,
        }
        return encryptors.get(algorithm, lambda x, y: None)

    def _get_decryptor(self, algorithm):
        decryptors = {
            'AES': self.encryption_library.decrypt_aes,
            'DES': self.encryption_library.decrypt_desq,
            'RSA': self.encryption_library.decrypt_rsa,
            'BF': self.encryption_library.decrypt_blowfish,
        }
        return decryptors.get(algorithm, lambda x, y: None)