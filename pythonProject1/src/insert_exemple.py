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

algRepo.insert(Algorithm(name="AES", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(name="DES", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(name="BF", framework="OpenSSL", symetric=True))
algRepo.insert(Algorithm(name="RSA", framework="OpenSSL", symetric=False))


algRepo.insert(Algorithm(name="AES", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(name="DES", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(name="BF", framework="PyCryptodome", symetric=True))
algRepo.insert(Algorithm(name="RSA", framework="PyCryptodome", symetric=False))


algRepo.insert(Algorithm(name="AES", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(name="DES", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(name="BF", framework="Cryptography", symetric=True))
algRepo.insert(Algorithm(name="RSA", framework="Cryptography", symetric=False))



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
