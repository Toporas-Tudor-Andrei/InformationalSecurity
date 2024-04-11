import time
from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.Adaptors import SymmetricEncryptionAdapter, AsymmetricEncryptionAdapter
from criptograpy_module.KeyGenerator import KeyGenerator
from criptograpy_module.OpenSSL import OpenSSL
from criptograpy_module.PyCryptodome import PyCryptodome
import os


def select_file():
    file_path = os.path.realpath(os.path.join(os.path.dirname(__file__), "../res/fisier_de_test.txt"))
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print("File not found. Please enter a valid file path.")
        return select_file()


def select_algorithm():
    print("Select encryption algorithm:")
    print("1. AES")
    print("2. RSA")
    choice = input("Enter your choice (1/2): ")
    if choice == '1':
        return 'AES'
    elif choice == '2':
        return 'RSA'
    else:
        print("Invalid choice. Please enter 1 or 2.")
        return select_algorithm()


def select_framework():
    print("Select encryption framework:")
    print("1. Cryptography")
    print("2. OpenSSL")
    print("3. PyCryptodome")
    choice = input("Enter your choice (1/2/3): ")
    if choice == '1':
        return Cryptography, "Cryptography"
    elif choice == '2':
        return OpenSSL, "OpenSSL"
    elif choice == '3':
        return PyCryptodome, "PyCryptodome"
    else:
        print("Invalid choice. Please enter 1, 2, or 3.")
        return select_framework()


if __name__ == "__main__":
    file_content = select_file()
    algorithms = ['AES', 'RSA']
    frameworks = [(Cryptography, "Cryptography"), (PyCryptodome, "PyCryptodome")]

    aes_key = KeyGenerator.generate_256_key()

    rsa_private_key, rsa_public_key = KeyGenerator.generate_rsa_key_pair()

    for algorithm in algorithms:
        for framework, framework_name in frameworks:
            adapter = AsymmetricEncryptionAdapter(framework)

            if algorithm == 'AES':
                public_key = aes_key
                private_key = public_key
            else:
                public_key = rsa_public_key
                private_key = rsa_private_key

            encryption_time, ciphertext = adapter.encrypt(file_content, public_key, algorithm)

            decryption_time, decrypted_content = adapter.decrypt(ciphertext, private_key, algorithm)

            file_name = f"{algorithm}_{framework_name}_encryption_performance.txt"
            with open(file_name, 'w') as f:
                f.write(f"Framework: {framework_name}\n")
                f.write(f"Algorithm: {algorithm}\n")
                f.write(f"Encryption Time: {encryption_time} seconds\n")
                f.write(f"Decryption Time: {decryption_time} seconds\n")
                f.write("Ciphertext:\n")
                f.write(str(ciphertext))
                f.write("\nDecrypted Content:\n")
                f.write(decrypted_content)

            print(
                f"Encryption and decryption with {algorithm} using {framework_name} completed. Results saved in {file_name}")
