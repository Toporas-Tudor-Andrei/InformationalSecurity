from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.EncryptionAdapter import EncryptionAdapter
from criptograpy_module.KeyGenerator import KeyGenerator
from criptograpy_module.OpenSSL import OpenSSL
from criptograpy_module.PyCryptodome import PyCryptodome
from src.bd import *

algRepo = Repository.of(Algorithm)
fileRepo = Repository.of(File)
keyRepo = Repository.of(Key)
perfRepo = Repository.of(PerformanceLogs)


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


if __name__ == "__main__":
    print(algRepo.findAll())
    print(getAlgorithms())
    print(getAlgorithmByFramework("OpenSSL"))
    print(getFrameworks())
    print(getFrameworkByAlgorithm("AES"))
    print(algRepo.findAll(Algorithm.name.in_(["AES", "DES"])))
    print(perfData())
    print(perfRepo.findAll())
