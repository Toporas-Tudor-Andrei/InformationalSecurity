from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Performance.Decorators import *
from cryptography.hazmat.primitives import padding


class Cryptography:
    """
    Quacks like a framework
    """
    @time_it
    @staticmethod
    def encrypt_aes(plaintext, key):
        if len(key) * 8 != 256:
            raise ValueError("Key length must be 256 bits")

        iv = b'\x00' * 16
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext)
        return iv + ciphertext

    @time_it
    @staticmethod
    def decrypt_aes(ciphertext, key):
        iv = ciphertext[:16]
        ciphertext_data = ciphertext[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

    @time_it
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext


    @time_it
    @staticmethod
    def decrypt_rsa(ciphertext, private_key):
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        plaintext = private_key.decrypt(
            ciphertext,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()









