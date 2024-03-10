from src.bd import *

def delete_all(session, Model):
    session.query(Model).delete()
    session.commit()

def delete_all_records():
    session = Session()
    delete_all(session, Algorithm)
    delete_all(session, File)
    delete_all(session, Key)
    delete_all(session, PerformanceLogs)
    session.close()

delete_all_records()

create_algorithm(id="1", name="AES", framework="PyCrypto")
create_algorithm(id="2", name="RSA", framework="OpenSSL")
create_algorithm(id="3", name="SHA-256", framework="Hashlib")


create_file(id="file1", bytes=1024, encrypted=True)
create_file(id="file2", bytes=2048, encrypted=False)


create_key(file_id="file1", algorithm_id="1", isprivate=True, encryptionkey="random_key_1")
create_key(file_id="file2", algorithm_id="2", isprivate=False, encryptionkey="random_key_2")




