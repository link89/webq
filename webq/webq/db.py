from sqlalchemy import create_engine , inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from contextlib import contextmanager

from .log import get_logger

logger = get_logger(__name__)

Base = declarative_base()


class DBComponent:
    def __init__(self) -> None:
        self.engine = None
        self.session_factory = None

    def init(self, db_url: str):
        assert db_url, "db_url is required"
        assert self.engine is None, "db is already initialized"
        logger.info('initializing engine: %s', db_url)
        self.engine = create_engine(db_url)
        assert self.session_factory is None, "db is already initialized"
        self.session_factory = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine)

    @contextmanager
    def get_db_session(self):
        db_session = self.session_factory()  # type: ignore
        try:
            yield db_session
        finally:
            db_session.close()

    def create_tables(self):
        # use the side effect of importing db_model to register models
        from .model import db as db_model
        # create tables
        Base.metadata.create_all(bind=self.engine)  # type: ignore
