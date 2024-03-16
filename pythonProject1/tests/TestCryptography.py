import unittest
from criptograpy_module.KeyGenerator import KeyGenerator
from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.OpenSSL import OpenSSL
from criptograpy_module.PyCryptodome import PyCryptodome
from criptograpy_module.EncryptionAdapter import EncryptionAdapter


class TestCryptography(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()
        self.aes_key = KeyGenerator.generate_aes_key()
        self.plaintext = "Hello, this is a secret message."

    def test_rsa_encryption_decryption(self):
        (time_performance, ciphertext) = Cryptography.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, decrypted_text) = Cryptography.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption(self):
        (time_performance, ciphertext) = Cryptography.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, decrypted_text) = Cryptography.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)


class TestPyCryptodome(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_aes_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption(self):
        (time_performance, ciphertext) = PyCryptodome.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, decrypted_text) = PyCryptodome.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption(self):
        (time_performance, ciphertext) = PyCryptodome.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, decrypted_text) = PyCryptodome.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)


class TestOpenSSL(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_aes_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption(self):
        (time_performance, ciphertext) = OpenSSL.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, decrypted_text) = OpenSSL.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption(self):
        (time_performance, ciphertext) = OpenSSL.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, decrypted_text) = OpenSSL.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)


class TestEncryptionAdapter(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_aes_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption_openssl(self):
        encryption_adapter = EncryptionAdapter(OpenSSL)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_openssl(self):
        encryption_adapter = EncryptionAdapter(OpenSSL)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption_cryptography(self):
        encryption_adapter = EncryptionAdapter(Cryptography)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_cryptography(self):
        encryption_adapter = EncryptionAdapter(Cryptography)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption_pycryptodome(self):
        encryption_adapter = EncryptionAdapter(PyCryptodome)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_pycryptodome(self):
        encryption_adapter = EncryptionAdapter(PyCryptodome)
        (time_performance, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)


if __name__ == '__main__':
    unittest.main()
