from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


Base = declarative_base()


class DBComponent:
    def __init__(self) -> None:
        self.engine = None
        self.session_factory = None

    def init(self, db_url: str):
        assert db_url, "db_url is required"
        if self.engine is None:
            print('initializing engine:', db_url)
            self.engine = create_engine(db_url)
        if self.session_factory is None:
            self.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_engine(self):
        assert self.engine, "engine not initialized"
        return self.engine

    def get_session_factory(self):
        assert self.session_factory, "session factory not initialized"
        return self.session_factory

    def get_db_session(self):
        session_factory = self.get_session_factory()
        db_session = session_factory()
        try:
            yield db_session
        finally:
            db_session.close()


_db = DBComponent()


# expose db functions
def init(db_url: str, db = _db):
    db.init(db_url)

def get_engine(db = _db):
    return db.get_engine()

def get_db_session(db = _db):
    return db.get_db_session()

def create_tables(db = _db):
    # use the side effect of importing db_model to register models
    from .model import db as db_model
    # create tables
    Base.metadata.create_all(bind=get_engine(db))  # type: ignore
