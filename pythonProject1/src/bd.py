from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

engine = create_engine('sqlite:///database.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)

class Algorithm(Base):
    __tablename__ = 'algorithm'

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    framework = Column(String, nullable=False)
    symetric = Column(Boolean, nullable=False)

class File(Base):
    __tablename__ = 'file'

    id = Column(String, primary_key=True)
    bytes = Column(Integer, nullable=False)
    encrypted = Column(Boolean, nullable=False)

class Key(Base):
    __tablename__ = 'key'

    id = Column(Integer, primary_key=True)
    file_id = Column(String, ForeignKey('file.id'), nullable=False)
    algorithm_id = Column(String, ForeignKey('algorithm.id'), nullable=False)
    isprivate = Column(Boolean, nullable=False)
    encryptionkey = Column(String, nullable=False)

    file = relationship('File')
    algorithm = relationship('Algorithm')

class PerformanceLogs(Base):
    __tablename__ = 'performance_logs'

    id = Column(Integer, primary_key=True)
    encoding_time = Column(DateTime, nullable=False)
    decoding_time = Column(DateTime, nullable=False)
    file_id = Column(String, ForeignKey('file.id'), nullable=False)
    algorithm_id = Column(String, ForeignKey('algorithm.id'), nullable=False)

    file = relationship('File')
    algorithm = relationship('Algorithm')

def create_algorithm(id, name, framework, symetric):
    session = Session()
    algorithm = Algorithm(id=id, name=name, framework=framework, symetric=symetric)
    session.add(algorithm)
    session.commit()
    session.close()

def read_algorithm(id):
    session = Session()
    algorithm = session.query(Algorithm).filter(Algorithm.id == id).first()
    session.close()
    return algorithm

def update_algorithm(id, name, framework, symetric):
    session = Session()
    algorithm = session.query(Algorithm).filter(Algorithm.id == id).first()
    algorithm.name = name
    algorithm.framework = framework
    algorithm.symetric = symetric
    session.commit()
    session.close()

def delete_algorithm(id):
    session = Session()
    algorithm = session.query(Algorithm).filter(Algorithm.id == id).first()
    session.delete(algorithm)
    session.commit()
    session.close()

def create_file(id, bytes, encrypted):
    session = Session()
    file = File(id=id, bytes=bytes, encrypted=encrypted)
    session.add(file)
    session.commit()
    session.close()

def read_file(id):
    session = Session()
    file = session.query(File).filter(File.id == id).first()
    session.close()
    return file

def update_file(id, bytes, encrypted):
    session = Session()
    file = session.query(File).filter(File.id == id).first()
    file.bytes = bytes
    file.encrypted = encrypted
    session.commit()
    session.close()

def delete_file(id):
    session = Session()
    file = session.query(File).filter(File.id == id).first()
    session.delete(file)
    session.commit()
    session.close()

def create_key(file_id, algorithm_id, isprivate, encryptionkey):
    session = Session()
    key = Key(file_id=file_id, algorithm_id=algorithm_id, isprivate=isprivate, encryptionkey=encryptionkey)
    session.add(key)
    session.commit()
    session.close()

def read_key(id):
    session = Session()
    key = session.query(Key).filter(Key.id == id).first()
    session.close()
    return key

def update_key(id, file_id, algorithm_id, isprivate, encryptionkey):
    session = Session()
    key = session.query(Key).filter(Key.id == id).first()
    key.file_id = file_id
    key.algorithm_id = algorithm_id
    key.isprivate = isprivate
    key.encryptionkey = encryptionkey
    session.commit()
    session.close()

def delete_key(id):
    session = Session()
    key = session.query(Key).filter(Key.id == id).first()
    session.delete(key)
    session.commit()
    session.close()

def create_performance_log(encoding_time, decoding_time, file_id, algorithm_id):
    session = Session()
    log = PerformanceLogs(encoding_time=encoding_time, decoding_time=decoding_time, file_id=file_id, algorithm_id=algorithm_id)
    session.add(log)
    session.commit()
    session.close()

def read_performance_log(id):
    session = Session()
    log = session.query(PerformanceLogs).filter(PerformanceLogs.id == id).first()
    session.close()
    return log

def update_performance_log(id, encoding_time, decoding_time, file_id, algorithm_id):
    session = Session()
    log = session.query(PerformanceLogs).filter(PerformanceLogs.id == id).first()
    log.encoding_time = encoding_time
    log.decoding_time = decoding_time
    log.file_id = file_id
    log.algorithm_id = algorithm_id
    session.commit()
    session.close()

def delete_performance_log(id):
    session = Session()
    log = session.query(PerformanceLogs).filter(PerformanceLogs.id == id).first()
    session.delete(log)
    session.commit()
    session.close()


Base.metadata.create_all(engine)
