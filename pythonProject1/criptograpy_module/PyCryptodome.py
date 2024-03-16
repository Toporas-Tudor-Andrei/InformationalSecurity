import os

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util import Padding

from Performance.Decorators import *


class PyCryptodome:
    @time_it
    @staticmethod
    def encrypt_aes(plaintext, key):
        if len(key) != 32:
            raise ValueError("Key length must be 256 bits")

        iv = b'\x00' * 16
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

