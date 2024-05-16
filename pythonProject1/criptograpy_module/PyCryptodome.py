import os
from Crypto.Cipher import PKCS1_OAEP, AES, DES3, Blowfish, DES
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from Performance.Decorators import stats

class PyCryptodome:
    """
    Quacks like a framework
    """
    @stats
    @staticmethod
    def encrypt_aes(plaintext, key, mode='ecb'):
        valid_key_sizes = [128, 192, 256]
        if (len(key) * 8) not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        if mode != 'ecb':
            iv = os.urandom(16)
        else:
            iv = b''

        if mode.lower() == 'ecb':
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = AES.new(key, AES.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        padded_plaintext = Padding.pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_aes(ciphertext, key, mode='ecb'):
        valid_key_sizes = [128, 192, 256]
        if (len(key) * 8) not in valid_key_sizes:
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
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = AES.new(key, AES.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        decrypted_text = cipher.decrypt(ciphertext_data)
        unpadded_text = Padding.unpad(decrypted_text, AES.block_size)
        return unpadded_text.decode()

    @stats
    @staticmethod
    def encrypt_des(plaintext, key, mode='ecb'):
        valid_key_sizes = [64]
        if (len(key) * 8) not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")


        if mode != 'ecb':
            iv = os.urandom(8)
        else:
            iv = b''

        if mode.lower() == 'ecb':
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = DES.new(key, DES.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = DES.new(key, DES.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        padded_plaintext = Padding.pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_des(ciphertext, key, mode='ecb'):
        valid_key_sizes = [64]
        if (len(key) * 8) not in valid_key_sizes:
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
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = DES.new(key, DES.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = DES.new(key, DES.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        decrypted_text = cipher.decrypt(ciphertext_data)
        unpadded_text = Padding.unpad(decrypted_text, DES.block_size)
        return unpadded_text.decode()




    @stats
    @staticmethod
    def encrypt_bf(plaintext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        if (len(key) * 8) not in valid_key_sizes:
            raise ValueError(f"Invalid key size for AES encryption. Choose from: {valid_key_sizes}")

        if mode.lower() not in ['ecb', 'cbc', 'cfb', 'ofb']:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'")

        if mode != 'ecb':
            iv = os.urandom(8)
        else:
            iv = b''

        if mode.lower() == 'ecb':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        padded_plaintext = Padding.pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    @stats
    @staticmethod
    def decrypt_bf(ciphertext, key, mode='ecb'):
        valid_key_sizes = [64, 128, 192, 256]
        if (len(key) * 8) not in valid_key_sizes:
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
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        elif mode.lower() == 'cbc':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        elif mode.lower() == 'cfb':
            cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        elif mode.lower() == 'ofb':
            cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)
        else:
            raise ValueError("Invalid mode. Supported modes are 'ecb', 'cbc', 'cfb', and 'ofb'.")

        decrypted_text = cipher.decrypt(ciphertext_data)
        unpadded_text = Padding.unpad(decrypted_text, Blowfish.block_size)
        return unpadded_text.decode()

    @stats
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    @stats
    @staticmethod
    def decrypt_rsa(ciphertext, private_key):
        private_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

