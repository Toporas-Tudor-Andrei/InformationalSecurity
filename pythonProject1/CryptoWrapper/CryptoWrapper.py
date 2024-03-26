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


def getAlgorithmByFramework(name):
    return list(filter(lambda x: x.framework == name, algRepo.findAll()))


if __name__ == "__main__":
    print(algRepo.findAll())
    print(getAlgorithms())
    print(getAlgorithmByFramework("OpenSSL"))
