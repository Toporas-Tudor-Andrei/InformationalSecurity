class EncryptionAdapter:
    def __init__(self, encryption_library):
        self.encryption_library = encryption_library

    def encrypt(self, plaintext, key, algorithm):
        return self._get_encryptor(algorithm)(plaintext, key)

    def decrypt(self, ciphertext, key, algorithm):
        return self._get_decryptor(algorithm)(ciphertext, key)

    def _get_encryptor(self, algorithm):
        encryptors = {
            'AES': self.encryption_library.encrypt_aes,
            'RSA': self.encryption_library.encrypt_rsa,
        }
        return encryptors.get(algorithm, lambda x, y: None)

    def _get_decryptor(self, algorithm):
        decryptors = {
            'AES': self.encryption_library.decrypt_aes,
            'RSA': self.encryption_library.decrypt_rsa,
        }
        return decryptors.get(algorithm, lambda x, y: None)