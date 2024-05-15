from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Float
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import os

dbFolder = os.path.dirname(__file__)
engine = create_engine(f'sqlite:///{dbFolder}/database.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)


class Repository:
    """
    Generic class that encapsulates the crud operations on a sqlalchemy entity class (derives Base)
    """
    def __init__(self, model, sessionMaker):
        self.__model = model
        self.__sessionMaker = sessionMaker
        self.session = None

    @staticmethod
    def of(model):
        """
        Factory method
        :param model: sqlalchemy entity class on witch to create the repository around
        :return: the created repository
        """
        return Repository(model, Session)

    def operation(func):
        """
        Decorator for handling sessions
        :return:
        """
        def inner(self, *args, **kwargs):
            self.session = self.__sessionMaker()
            try:
                return func(self, *args, **kwargs)
            except DBAPIError as e:
                raise e
            finally:
                self.session.close()
        return inner

    @operation
    def insert(self, obj):
        self.session.add(obj)
        self.session.commit()

    @operation
    def update(self, *query, update):
        result = self._findAll(*query).first()[0]
        for key in vars(update):
            if not key.startswith('_'):
                setattr(result, key, getattr(update, key))
        self.session.commit()

    def _findAll(self, *args):
        return self.session.execute(self.session.query(self.__model).filter(*args))

    @operation
    def findAll(self, *args):
        return list(map(lambda x: x[0], self._findAll(*args).fetchall()))

    @operation
    def delete(self, *args):
        self.session.delete(self._findAll(*args).first()[0])
        self.session.commit()

    @operation
    def deleteAll(self):
        self.session.query(self.__model).delete()
        self.session.commit()

    @operation
    def getLastId(self):
        # Get the ID of the last inserted record from the Algorithm table
        last_id = self.session.query(self.__model.id).order_by(self.__model.id.desc()).first()
        return last_id[0] if last_id else None

    @operation
    def findAllJoinOn(self, joinModel, *args):
        return self.session.execute(self.session.query(self.__model, joinModel).join(joinModel).filter(*args)).fetchall()


class Printable:
    def __str__(self):
        rpr = ",\n".join([f"{prop}={getattr(self, prop)}" for prop in self.__dict__
                          if not callable(getattr(self, prop)) and not prop.startswith("_")])
        return f"{{\n{rpr}\n}}"

    def __repr__(self):
        return self.__str__().replace("\n", "")


class Algorithm(Base, Printable):
    __tablename__ = 'algorithm'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    framework = Column(String, nullable=False)
    symetric = Column(Boolean, nullable=False)
    mode = Column(String, nullable=True) # For rsa can be nullable
    key_len = Column(Integer, nullable=True)


class File(Base, Printable):
    __tablename__ = 'file'

    id = Column(Integer, primary_key=True, autoincrement="auto")
    hash = Column(String, nullable=False)
    bytes = Column(Integer, nullable=False)
    encrypted = Column(Boolean, nullable=False)


class Key(Base, Printable):
    __tablename__ = 'key'

    id = Column(Integer, primary_key=True, autoincrement="auto")
    file_id = Column(String, ForeignKey('file.id'), nullable=False)
    algorithm_id = Column(String, ForeignKey('algorithm.id'), nullable=False)
    isprivate = Column(Boolean, nullable=False)
    encryptionkey = Column(String, nullable=False)

    file = relationship('File')
    algorithm = relationship('Algorithm')


class PerformanceLogs(Base, Printable):
    __tablename__ = 'performance_logs'

    id = Column(Integer, primary_key=True, autoincrement="auto")
    encoding_time = Column(Float, nullable=False)
    decoding_time = Column(Float, nullable=False)
    mem_usage_enc = Column(Float, nullable=False)
    mem_usage_dec = Column(Float, nullable=False)
    file_id = Column(String, ForeignKey('file.id'), nullable=False)
    algorithm_id = Column(String, ForeignKey('algorithm.id'), nullable=False)

    file = relationship('File')
    algorithm = relationship('Algorithm')


Base.metadata.create_all(engine)
