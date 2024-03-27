import os
from Crypto.Cipher import PKCS1_OAEP, AES, DES3, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from Performance.Decorators import *

class PyCryptodome:
    """
    Quacks like a framework
    """
    @time_it
    @staticmethod
    def encrypt_aes(plaintext, key):
        if len(key) != 32:
            raise ValueError("Key length must be 256 bits")

        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = Padding.pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @time_it
    @staticmethod
    def decrypt_aes(ciphertext, key):
        if len(key) != 32:
            raise ValueError("Key length must be 256 bits")

        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = Padding.unpad(decrypted_text, AES.block_size)
        return unpadded_text.decode()

    @time_it
    @staticmethod
    def encrypt_3des(plaintext, key):
        if len(key) != 24:
            raise ValueError("Key length must be 64 bits")

        iv = os.urandom(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded_plaintext = Padding.pad(plaintext.encode(), DES3.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @time_it
    @staticmethod
    def decrypt_3des(ciphertext, key):
        if len(key) != 24:
            raise ValueError("Key length must be 192 bits")

        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = Padding.unpad(decrypted_text, DES3.block_size)
        return unpadded_text.decode()

    @time_it
    @staticmethod
    def encrypt_blowfish(plaintext, key):
        iv = os.urandom(8)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded_plaintext = Padding.pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @time_it
    @staticmethod
    def decrypt_blowfish(ciphertext, key):
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(ciphertext)
        unpadded_text = Padding.unpad(decrypted_text, Blowfish.block_size)
        return unpadded_text.decode()

    @time_it
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    @time_it
    @staticmethod
    def decrypt_rsa(ciphertext, private_key):
        private_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

