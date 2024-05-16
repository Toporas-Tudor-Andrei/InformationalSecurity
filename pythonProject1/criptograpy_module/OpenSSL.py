import os
import subprocess
import tempfile
from base64 import *

from Performance.Decorators import stats

class OpenSSL:
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

        iv = os.urandom(16)

        iv_hex = iv.hex()
        key_hex = key.hex()
        openssl_cmd = f'echo -n "{plaintext}" | openssl enc -aes-{key_size}-{mode} -base64 -K {key_hex} -iv {iv_hex}'
        encrypted_text = b64decode(subprocess.check_output(openssl_cmd, shell=True))
        return iv + encrypted_text.strip()

    @stats
    @staticmethod
    def decrypt_aes(ciphertext, key, mode='ecb'):
        valid_key_sizes = [128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        iv = ciphertext[:16]
        ciphertext_data = ciphertext[16:]
        iv_hex = iv.hex()
        key_hex = key.hex()
        ciphertext_data_hex = b64encode(ciphertext_data).decode('utf-8')
        openssl_cmd = f'echo -n "{ciphertext_data_hex}" | base64 -d | openssl enc -d -aes-{key_size}-{mode} -K {key_hex} -iv {iv_hex}'
        decrypted_text = subprocess.check_output(openssl_cmd, shell=True).decode()
        return decrypted_text.strip()

    @stats
    @staticmethod
    def encrypt_des(plaintext, key, mode='ecb'):
        valid_key_sizes = [64]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        # Generate a random IV
        iv = os.urandom(8)

        iv_hex = iv.hex()
        key_hex = key.hex()
        openssl_cmd = f'echo -n "{plaintext}" | openssl enc -des-{mode} -base64 -K {key_hex} -iv {iv_hex} -provider legacy'
        encrypted_text = b64decode(subprocess.check_output(openssl_cmd, shell=True))
        return iv + encrypted_text.strip()

    @stats
    @staticmethod
    def decrypt_des(ciphertext, key, mode='ecb'):
        valid_key_sizes = [64]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        iv = ciphertext[:8]
        ciphertext_data = ciphertext[8:]
        iv_hex = iv.hex()
        key_hex = key.hex()
        ciphertext_data_hex = b64encode(ciphertext_data).decode('utf-8')
        openssl_cmd = f'echo -n "{ciphertext_data_hex}" | base64 -d | openssl enc -d -des-{mode} -K {key_hex} -iv {iv_hex} -provider legacy'
        decrypted_text = subprocess.check_output(openssl_cmd, shell=True).decode()
        return decrypted_text.strip()

    @stats
    @staticmethod
    def encrypt_bf(plaintext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        # Generate a random IV
        iv = os.urandom(8)

        iv_hex = iv.hex()
        key_hex = key.hex()
        openssl_cmd = f'echo -n "{plaintext}" | openssl enc -bf-{mode} -base64 -K {key_hex} -iv {iv_hex} -provider legacy'
        encrypted_text = b64decode(subprocess.check_output(openssl_cmd, shell=True))
        return iv + encrypted_text.strip()

    @stats
    @staticmethod
    def decrypt_bf(ciphertext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        key_size = (len(key) * 8)
        if key_size not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        iv = ciphertext[:8]
        ciphertext_data = ciphertext[8:]
        iv_hex = iv.hex()
        key_hex = key.hex()
        ciphertext_data_hex = b64encode(ciphertext_data).decode('utf-8')
        openssl_cmd = f'echo -n "{ciphertext_data_hex}" | base64 -d | openssl enc -d -bf-{mode} -K {key_hex} -iv {iv_hex} -provider legacy'
        decrypted_text = subprocess.check_output(openssl_cmd, shell=True).decode()
        return decrypted_text.strip()

    @stats
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        """Encrypt the plaintext using RSA."""
        # public key to temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_public_key_file:
            temp_public_key_file.write(public_key)
            temp_public_key_file_name = temp_public_key_file.name

        # plaintext to temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_text_file:
            temp_text_file.write(plaintext)
            temp_text_file_name = temp_text_file.name

        # encrypt the plaintext using openssl command
        openssl_cmd = f'openssl pkeyutl -encrypt -pubin -inkey {temp_public_key_file_name} -in {temp_text_file_name} -out encrypted_text.enc'
        subprocess.run(openssl_cmd, shell=True, check=True)

        # remove temporary files
        os.unlink(temp_public_key_file_name)
        os.unlink(temp_text_file_name)

        # read and return the encrypted text
        with open('encrypted_text.enc', 'rb') as encrypted_file:
            encrypted_text = encrypted_file.read()

        return encrypted_text

    @stats
    @staticmethod
    def decrypt_rsa(ciphertext, private_key):
        """Decrypt the ciphertext using RSA."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_private_key_file:
            temp_private_key_file.write(private_key)
            temp_private_key_file_name = temp_private_key_file.name

        with tempfile.NamedTemporaryFile(delete=False) as temp_cipher_file:
            temp_cipher_file.write(ciphertext)
            temp_cipher_file_name = temp_cipher_file.name

        # The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
        openssl_cmd = f'openssl pkeyutl -decrypt -in {temp_cipher_file_name} -inkey {temp_private_key_file_name} -out decrypted_text.txt'
        subprocess.run(openssl_cmd, shell=True, check=True)

        os.unlink(temp_private_key_file_name)
        os.unlink(temp_cipher_file_name)

        with open('decrypted_text.txt', 'r') as decrypted_file:
            decrypted_text = decrypted_file.read()

        return decrypted_text

