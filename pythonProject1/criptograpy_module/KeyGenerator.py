import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyGenerator:
    @staticmethod
    def generate_256_key():
        """Generate a 256-bit key"""
        return os.urandom(32)

    @staticmethod
    def generate_192_key():
        """Generate a 192-bit key"""
        return os.urandom(24)

    @staticmethod
    def generate_128_key():
        """Generate a 128-bit key"""
        return os.urandom(16)

    @staticmethod
    def generate_64_key():
        """Generate a 64-bit key"""
        return os.urandom(8)

    @staticmethod
    def generate_rsa_key_pair():
        """Generate an RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key_pem, public_key_pem
