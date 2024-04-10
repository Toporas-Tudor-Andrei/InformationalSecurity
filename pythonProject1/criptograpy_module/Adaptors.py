class SymmetricEncryptionAdapter:
    """
    Class that encapsulates multiple framework, algorithm pairs for ease of use
    """
    def __init__(self, encryption_library):
        """
        Constructor
        :param encryption_library: class that quacks like a framework
        """
        self.encryption_library = encryption_library

    def encrypt(self, plaintext, key, algorithm, mode='ecb'):
        return self._get_encryptor(algorithm)(plaintext, key, mode)

    def decrypt(self, ciphertext, key, algorithm, mode='ecb'):
        return self._get_decryptor(algorithm)(ciphertext, key, mode)

    def _get_encryptor(self, algorithm):
        try:
            return getattr(self.encryption_library, f'encrypt_{algorithm.lower()}')
        except AttributeError:
            return lambda x, y, z: None

    def _get_decryptor(self, algorithm):
        try:
            return getattr(self.encryption_library, f'decrypt_{algorithm.lower()}')
        except AttributeError:
            return lambda x, y, z: None
###############################################################
class AsymmetricEncryptionAdapter:
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
        try:
            return getattr(self.encryption_library, f'encrypt_{algorithm.lower()}')
        except AttributeError:
            return lambda x, y, z: None

    def _get_decryptor(self, algorithm):
        try:
            return getattr(self.encryption_library, f'decrypt_{algorithm.lower()}')
        except AttributeError:
            return lambda x, y, z: None