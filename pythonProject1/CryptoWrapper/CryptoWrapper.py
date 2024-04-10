from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.Adaptors import SymmetricEncryptionAdapter, AsymmetricEncryptionAdapter
from criptograpy_module.KeyGenerator import KeyGenerator
from criptograpy_module.OpenSSL import OpenSSL
from criptograpy_module.PyCryptodome import PyCryptodome
from src.bd import *
import hashlib

algRepo = Repository.of(Algorithm)
fileRepo = Repository.of(File)
keyRepo = Repository.of(Key)
perfRepo = Repository.of(PerformanceLogs)

keyGen = KeyGenerator


def calculate_sha256_hash(data):
    """
    Calculates the SHA256 for hash in table file
    """
    # Convert data to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')

    sha256_hash = hashlib.sha256(data).hexdigest()

    return sha256_hash

def getAlgorithms():
    return algRepo.findAll()


def getAlgorithmByFramework(framework):
    return algRepo.findAll(Algorithm.framework == framework)


def getFrameworks():
    return set(map(lambda x: x.framework, algRepo.findAll()))


def getFrameworkByAlgorithm(algorithm):
    return set(map(lambda x: x.framework, algRepo.findAll(Algorithm.name == algorithm)))


def perfData(fileId=None, /, *, alg=None, framework=None):
    """
    Query function for finding the representative performance rows in the database
    :param fileId: filter parameter for finding a certain file's data
    :param alg: filter parameter for algorithm name
    :param framework: filter parameter for framework name
    :return: a list of PerformanceLogs objects corresponding to the filters given as parameters
    """
    filters = [getattr(Algorithm, col) == val for col, val in
               [("name", alg), ("framework", framework)] if val is not None]
    ids = list(map(lambda it: it.id, algRepo.findAll(*filters)))

    file_cond = [getattr(PerformanceLogs, col) == val for col, val in
                 [("file_id", fileId)] if val is not None]

    return perfRepo.findAll(*file_cond, PerformanceLogs.algorithm_id.in_(ids))


def logsProcessing(logs, operation, target):
    """
    Applies certain reductions on the performance logs gives as input
    :param logs: a list of PerformanceLogs objects to be aggregated
    :param operation: reduction method can take the values: "avg", "max", "min", "" - for no reduction
    :param target: slice of data to be used in the reduction can take the values:
        "enc", "dec", "diff" - difference between encoding and decoding time, default "enc"
    :return: the result of the reduction operation
    """
    if target == "enc":
        data = list(map(lambda it: it.encoding_time, logs))
    elif target == "dec":
        data = list(map(lambda it: it.decoding_time, logs))
    elif target == "diff":
        data = list(map(lambda it: it.encoding_time - it.decoding_time, logs))
    else:
        data = list(map(lambda it: it.encoding_time, logs))

    if operation == "avg":
        return sum(data)/len(data)
    elif operation == "min":
        min(data)
    elif operation == "max":
        max(data)
    else:
        return data

def getAlgorithmModes(framework, algorithm):
    """
    Returns the list of available algorithm modes for each pair of fw-algorithm
    """
    matching_entries = algRepo.findAll(Algorithm.framework == framework, Algorithm.name == algorithm)
    modes = set(entry.mode for entry in matching_entries if entry.mode)
    return list(modes)

def getAlgorithmKeysLesngths(framework, algorithm):
    """
    Returns list of available key lengths for each pair of fw-algorithm
    """
    matching_entries = algRepo.findAll(Algorithm.framework == framework, Algorithm.name == algorithm)
    lengths = set(entry.key_len for entry in matching_entries if entry.key_len)
    return list(lengths)


def encode_with_performance_measurment_simetric(plaintext, framework, algorithm, key, mode='ecb'):
    """
    Functie de apelat la encoding cu algoritm simetric(aes, des, bf)
    Returns cryptotext
    Registeres encryption and decription performances in performance logs
    """
    if framework.lower() == "openssl":
        encryption_adapter = SymmetricEncryptionAdapter(OpenSSL)
    elif framework.lower() == "pycryptodome":
        encryption_adapter = SymmetricEncryptionAdapter(PyCryptodome)
    elif framework.lower() == "cryptography":
        encryption_adapter = SymmetricEncryptionAdapter(Cryptography)
    else:
        raise ValueError("Invalid framework specified.")

    (time_performance_enc, ciphertext) = encryption_adapter.encrypt(plaintext, key, algorithm, mode)

    # 1. Register in file table
    fileRepo.insert(File(hash=calculate_sha256_hash(plaintext), bytes=len(plaintext.encode('utf-8')), encrypted=False))
    id_file = fileRepo.getLastId()
    fileRepo.insert(File(hash=calculate_sha256_hash(ciphertext), bytes=len(plaintext.encode('utf-8')), encrypted=True))
    id_encoded_file = fileRepo.getLastId()

    # 2. Register in key table
    algorithm_id = algRepo.findAll(Algorithm.framework == framework,
                                   Algorithm.name == algorithm,
                                   Algorithm.mode == mode,
                                   Algorithm.key_len == (len(key) * 8))[0].id

    keyRepo.insert(Key(file_id=id_file, algorithm_id=algorithm_id, isprivate=False, encryptionkey=key))
    keyRepo.insert(Key(file_id=id_encoded_file, algorithm_id=algorithm_id, isprivate=False, encryptionkey=key))

    # 3. Register in performances table
    (time_performance_dec, decrypted_text) = encryption_adapter.decrypt(ciphertext, key, algorithm, mode)
    perfRepo.insert(PerformanceLogs(encoding_time=time_performance_enc, decoding_time=time_performance_dec, file_id=id_file, algorithm_id=algorithm_id))

if __name__ == "__main__":
    print(algRepo.findAll())
    print(getAlgorithms())
    print(getAlgorithmByFramework("OpenSSL"))
    print(getFrameworks())
    print(getFrameworkByAlgorithm("AES"))
    print(algRepo.findAll(Algorithm.name.in_(["AES", "DES"])))
    print(perfData())
    print(perfRepo.findAll())

    # lista cu moduri de rulare disponibile pt un alg
    modes = getAlgorithmModes("OpenSSL", "AES")
    print(modes)

    # lista cu lungimile cheilor pt generare
    keys = getAlgorithmKeysLesngths("OpenSSL", "AES")
    print(keys)

    # encoding simetric
    plaintext = "Ana are mere."
    key = keyGen.generate_64_key()
    encode_with_performance_measurment_simetric(plaintext, framework="OpenSSL", algorithm="DES", key= key, mode='cbc')

