import unittest
from criptograpy_module.KeyGenerator import KeyGenerator
from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.OpenSSL import OpenSSL
from criptograpy_module.PyCryptodome import PyCryptodome
from criptograpy_module.Adaptors import SymmetricEncryptionAdapter, AsymmetricEncryptionAdapter


class TestCryptography(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()
        self.aes_key = KeyGenerator.generate_256_key()
        self.des_key = KeyGenerator.generate_192_key()
        self.blowfish_key = KeyGenerator.generate_64_key()
        self.plaintext = "Hello, this is a secret message."

    def test_rsa_encryption_decryption(self):
        (time_performance, mem, ciphertext) = Cryptography.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, mem, decrypted_text) = Cryptography.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption(self):
        (time_performance, mem, ciphertext) = Cryptography.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, mem, decrypted_text) = Cryptography.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_des_encryption_decryption(self):
        (time_performance, mem, ciphertext) = Cryptography.encrypt_3des(self.plaintext, self.des_key)
        (time_performance, mem, decrypted_text) = Cryptography.decrypt_3des(ciphertext, self.des_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_blowfish_encryption_decryption(self):
        (time_performance, mem, ciphertext) = Cryptography.encrypt_bf(self.plaintext, self.blowfish_key)
        (time_performance, mem, decrypted_text) = Cryptography.decrypt_bf(ciphertext, self.blowfish_key)
        self.assertEqual(decrypted_text, self.plaintext)


class TestPyCryptodome(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_256_key()
        self.des_key = KeyGenerator.generate_64_key()
        self.blowfish_key = KeyGenerator.generate_64_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption(self):
        (time_performance, mem, ciphertext) = PyCryptodome.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, mem, decrypted_text) = PyCryptodome.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_des_encryption_decryption(self):
        (time_performance, mem, ciphertext) = PyCryptodome.encrypt_des(self.plaintext, self.des_key)
        (time_performance, mem, decrypted_text) = PyCryptodome.decrypt_des(ciphertext, self.des_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption(self):
        (time_performance, mem, ciphertext) = PyCryptodome.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, mem, decrypted_text) = PyCryptodome.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_blowfish_encryption_decryption(self):
        (time_performance, mem, ciphertext) = PyCryptodome.encrypt_bf(self.plaintext, self.blowfish_key)
        (time_performance, mem, decrypted_text) = PyCryptodome.decrypt_bf(ciphertext, self.blowfish_key)
        self.assertEqual(decrypted_text, self.plaintext)


class TestOpenSSL(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_256_key()
        self.des_key = KeyGenerator.generate_192_key()
        self.blowfish_key = KeyGenerator.generate_64_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption(self):
        (time_performance, mem, ciphertext) = OpenSSL.encrypt_aes(self.plaintext, self.aes_key)
        (time_performance, mem, decrypted_text) = OpenSSL.decrypt_aes(ciphertext, self.aes_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_des_encryption_decryption(self):
        (time_performance, mem, ciphertext) = OpenSSL.encrypt_des(self.plaintext, self.blowfish_key)
        (time_performance, mem, decrypted_text) = OpenSSL.decrypt_des(ciphertext, self.blowfish_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption(self):
        (time_performance, mem, ciphertext) = OpenSSL.encrypt_rsa(self.plaintext, self.public_key)
        (time_performance, mem, decrypted_text) = OpenSSL.decrypt_rsa(ciphertext, self.private_key)
        self.assertEqual(decrypted_text, self.plaintext)

    def test_blowfish_encryption_decryption(self):
        (time_performance, mem, ciphertext) = OpenSSL.encrypt_bf(self.plaintext, self.blowfish_key)
        (time_performance, mem, decrypted_text) = OpenSSL.decrypt_bf(ciphertext, self.blowfish_key)
        self.assertEqual(decrypted_text, self.plaintext)

class TestEncryptionAdapter(unittest.TestCase):
    def setUp(self):
        print(f"\nClass: {self.__class__.__name__}")
        self.plaintext = "Hello, this is a secret message."
        self.aes_key = KeyGenerator.generate_256_key()
        self.des3_key = KeyGenerator.generate_192_key()
        self.des_key = KeyGenerator.generate_64_key()
        self.blowfish_key = KeyGenerator.generate_64_key()
        self.private_key, self.public_key = KeyGenerator.generate_rsa_key_pair()

    def test_aes_encryption_decryption_openssl(self):
        encryption_adapter = SymmetricEncryptionAdapter(OpenSSL)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_openssl(self):
        encryption_adapter = AsymmetricEncryptionAdapter(OpenSSL)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_3des_encryption_decryption_openssl(self):
        encryption_adapter = SymmetricEncryptionAdapter(OpenSSL)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.des_key, 'DES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.des_key, 'DES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_bf_encryption_decryption_openssl(self):
        encryption_adapter = SymmetricEncryptionAdapter(OpenSSL)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.blowfish_key, 'BF')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.blowfish_key, 'BF')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption_cryptography(self):
        encryption_adapter = SymmetricEncryptionAdapter(Cryptography)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_cryptography(self):
        encryption_adapter = AsymmetricEncryptionAdapter(Cryptography)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_3des_encryption_decryption_cryptography(self):
        encryption_adapter = SymmetricEncryptionAdapter(Cryptography)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.des3_key, '3DES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.des3_key, '3DES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_bf_encryption_decryption_cryptography(self):
        encryption_adapter = SymmetricEncryptionAdapter(Cryptography)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.blowfish_key, 'BF')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.blowfish_key, 'BF')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_aes_encryption_decryption_pycryptodome(self):
        encryption_adapter = SymmetricEncryptionAdapter(PyCryptodome)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.aes_key, 'AES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.aes_key, 'AES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_rsa_encryption_decryption_pycryptodome(self):
        encryption_adapter = AsymmetricEncryptionAdapter(PyCryptodome)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.public_key, 'RSA')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.private_key, 'RSA')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_3des_encryption_decryption_pycryptodome(self):
        encryption_adapter = SymmetricEncryptionAdapter(PyCryptodome)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.des_key, 'DES')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.des_key, 'DES')
        self.assertEqual(decrypted_text, self.plaintext)

    def test_bf_encryption_decryption_pycryptodome(self):
        encryption_adapter = SymmetricEncryptionAdapter(PyCryptodome)
        (time_performance, mem, ciphertext) = encryption_adapter.encrypt(self.plaintext, self.blowfish_key, 'BF')
        (time_performance, mem, decrypted_text) = encryption_adapter.decrypt(ciphertext, self.blowfish_key, 'BF')
        self.assertEqual(decrypted_text, self.plaintext)



if __name__ == '__main__':
    unittest.main()
