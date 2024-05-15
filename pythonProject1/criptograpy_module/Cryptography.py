import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from Performance.Decorators import stats


class Cryptography:
    """
    Quacks like a framework
    """

    @stats
    @staticmethod
    def encrypt_aes(plaintext, key, mode='ecb'):
        valid_key_sizes = [128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        # Generate a random IV if mode is not ECB
        if mode != 'ecb':
            iv = os.urandom(16)
        else:
            iv = b''
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_aes(ciphertext, key, mode='ecb'):
        valid_key_sizes = [128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        if mode != 'ecb':
            iv = ciphertext[:16]
            ciphertext_data = ciphertext[16:]
        else:
            iv = b''
            ciphertext_data = ciphertext

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

    @stats
    @staticmethod
    def encrypt_3des(plaintext, key, mode='ecb'):
        valid_key_sizes = [192]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        # Generate a random IV if mode is not ECB
        if mode != 'ecb':
            iv = os.urandom(8)
        else:
            iv = b''

        padder = padding.PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.TripleDES(key), cipher_mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_3des(ciphertext, key, mode='ecb'):
        valid_key_sizes = [192]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        if mode != 'ecb':
            iv = ciphertext[:8]
            ciphertext_data = ciphertext[8:]
        else:
            iv = b''
            ciphertext_data = ciphertext

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.TripleDES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()

        unpadder = padding.PKCS7(64).unpadder()
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

    @stats
    @staticmethod
    def encrypt_bf(plaintext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        # Generate a random IV if mode is not ECB
        if mode != 'ecb':
            iv = os.urandom(8)
        else:
            iv = b''

        padder = padding.PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.Blowfish(key), cipher_mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_bf(ciphertext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        if mode != 'ecb':
            iv = ciphertext[:8]
            ciphertext_data = ciphertext[8:]
        else:
            iv = b''
            ciphertext_data = ciphertext

        if mode.lower() == 'ecb':
            cipher_mode = modes.ECB()
        elif mode.lower() == 'cbc':
            cipher_mode = modes.CBC(iv)
        elif mode.lower() == 'cfb':
            cipher_mode = modes.CFB(iv)
        elif mode.lower() == 'ofb':
            cipher_mode = modes.OFB(iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        cipher = Cipher(algorithms.Blowfish(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()

        unpadder = padding.PKCS7(64).unpadder()
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

    @stats
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @stats
    @staticmethod
    def decrypt_rsa(ciphertext, private_key):
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        plaintext = private_key.decrypt(
            ciphertext,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
