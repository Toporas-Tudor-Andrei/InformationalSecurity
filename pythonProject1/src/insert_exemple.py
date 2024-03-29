from src.bd import *

algRepo = Repository.of(Algorithm)
fileRepo = Repository.of(File)
keyRepo = Repository.of(Key)
perfRepo = Repository.of(PerformanceLogs)


def delete_all_records():
    algRepo.deleteAll()
    fileRepo.deleteAll()
    keyRepo.deleteAll()
    perfRepo.deleteAll()


delete_all_records()

algRepo.insert(Algorithm(id="1", name="AES", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(id="2", name="DES", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(id="3", name="BF", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(id="4", name="RSA", framework="OpenSSL", symetric=False))


algRepo.insert(Algorithm(id="5", name="AES", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(id="6", name="DES", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(id="7", name="BF", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(id="8", name="RSA", framework="PyCryptodome", symetric=False))


algRepo.insert(Algorithm(id="9", name="AES", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(id="10", name="DES", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(id="11", name="BF", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(id="12", name="RSA", framework="Cryptography", symetric=False))



print(algRepo.findAll())
#
# fileRepo.insert(File(id="file1", hash="20894vucbgh209v", bytes=1024, encrypted=True))
# fileRepo.insert(File(id="file2", hash="920uc3rbn2093ub", bytes=2048, encrypted=False))
#
# keyRepo.insert(Key(file_id="file1", algorithm_id="1", isprivate=True, encryptionkey="random_key_1"))
# keyRepo.insert(Key(file_id="file2", algorithm_id="2", isprivate=False, encryptionkey="random_key_2"))
#
#
# algRepo.insert(Algorithm(id="4", name="TwoFish", framework="PyCrypto", symetric=True))
# algRepo.delete(Algorithm.id == "4")
# print(algRepo.findAll(Algorithm.framework == "PyCrypto"))
# algRepo.update(Algorithm.id == 1, update=Algorithm(name="TwoFish"))
# print(algRepo.findAll(Algorithm.framework == "PyCrypto"))
