from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import relationship

from datetime import datetime
from enum import IntEnum, IntFlag

from ..db import Base
# The below is constant for the database
# You should not change it unless you know what you are doing

S_SHORT = 256  # the max length of email is 254 chars
S_LONG = 4096  # the size of page is 4KB


class UserPerm(IntFlag):
    ADMIN = 1
    CREATE_JOB_QUEUE = 2


class JobQueuePerm(IntFlag):
    OWNER = 1
    CREATE_JOB = 2
    APPLY_OFFER = 4
    VIEW_ALL_JOB = 8
    VIEW_ALL_OFFER = 16


class JobState(IntEnum):
    DRAFT = 0
    READY = 1  # a job in ready state should be immutable


class OfferState(IntEnum):
    PENDING = 0
    RESOLVED = 1
    REJECTED = 2
    TIMEOUT = 3


class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class FileMixin:
    id = Column(Integer, primary_key=True)
    prefix = Column(String(S_LONG))
    url = Column(String(S_LONG))


class User(Base, TimestampMixin):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(S_SHORT), unique=True)
    password = Column(String(S_SHORT))
    salt = Column(String(S_SHORT))
    permission = Column(Integer, default=0)
    note = Column(Text, default='')


class Session(Base, TimestampMixin):
    __tablename__ = 'session'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(S_SHORT), unique=True)

    user_id = Column(Integer, index=True)
    user = relationship('User',
                        foreign_keys=[user_id],
                        primaryjoin='User.id == Session.user_id',
                        backref='sessions')



class UserToken(Base, TimestampMixin):
    __tablename__ = 'user_token'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(S_SHORT), unique=True)
    note = Column(Text, default='')

    user_id = Column(Integer, index=True)
    user = relationship('User',
                        foreign_keys=[user_id],
                        primaryjoin='User.id == UserToken.user_id',
                        backref='tokens')


class JobQueue(Base, TimestampMixin):
    __tablename__ = 'job_queue'

    id = Column(Integer, primary_key=True)
    name = Column(String(S_SHORT), index=True)
    note = Column(Text, default='')

    is_deleted = Column(Integer, default=0, index=True)

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == JobQueue.owner_id',
                         backref='job_queues')


class JobQueueMember(Base, TimestampMixin):
    __tablename__ = 'job_queue_member'

    id = Column(Integer, primary_key=True)
    permission = Column(Integer)

    is_deleted = Column(Integer, default=0, index=True)

    jobq_id = Column(Integer, index=True)
    jobq = relationship('JobQueue',
                        foreign_keys=[jobq_id],
                        primaryjoin='JobQueue.id == JobQueueMember.jobq_id',
                        backref='members')

    user_id = Column(Integer, index=True)
    user = relationship('User',
                        foreign_keys=[user_id],
                        primaryjoin='User.id == JobQueueMember.user_id',
                        backref='job_queue_members')


class Job(Base, TimestampMixin):
    __tablename__ = 'job'
    id = Column(Integer, primary_key=True)

    flt_str = Column(String, index=True)
    data = Column(JSON)
    state = Column(Integer, index=True)

    is_deleted = Column(Integer, default=0, index=True)

    jobq_id = Column(Integer, index=True)
    jobq = relationship('JobQueue',
                        foreign_keys=[jobq_id],
                        primaryjoin='JobQueue.id == Job.jobq_id',
                        backref='jobs')

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == Job.owner_id',
                         backref='jobs')


class JobFile(Base, FileMixin):
    __tablename__ = 'job_file'

    job_id = Column(Integer, index=True)
    job = relationship('Job',
                       foreign_keys=[job_id],
                       primaryjoin='Job.id == JobFile.job_id',
                       backref='files')


class Offer(Base, TimestampMixin):
    __tablename__ = 'offer'

    id = Column(Integer, primary_key=True)

    data = Column(JSON)
    state = Column(Integer, index=True)


    job_id = Column(Integer, index=True)
    job = relationship('Job',
                       foreign_keys=[job_id],
                       primaryjoin='Job.id == Offer.job_id',
                       backref='offers')

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == Offer.owner_id',
                         backref='offers')


class OfferFile(Base, FileMixin):
    __tablename__ = 'offer_file'

    offer_id = Column(Integer, index=True)
    offer = relationship('Offer',
                         foreign_keys=[offer_id],
                         primaryjoin='Offer.id == OfferFile.offer_id',
                         backref='files')
