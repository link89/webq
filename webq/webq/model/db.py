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

    VIEW_USERS = 2
    CREATE_USER = 4
    UPDATE_USER = 8

    VIEW_JOB_QUEUES = 16
    CREATE_JOB_QUEUE = 32
    UPDATE_JOB_QUEUE = 64


class JobQueuePerm(IntFlag):
    ADMIN = 1

    VIEW_JOBS = 2
    CREATE_JOB = 4
    UPDATE_JOB = 8  # update any job in the queue

    APPLY_JOB = 16

    VIEW_COMMITS = 32
    CREATE_COMMIT = 64
    UPDATE_COMMIT = 128  # update any commit in the queue


class JobState(IntEnum):
    # set by crowdsourcer
    DRAFT = 0
    READY = 1


class CommitState(IntEnum):
    # set by worker
    PENDING = 0
    ABORTED = 1
    DONE = 2
    # set by job owner/supervisor
    REJECTED = 3
    ACCEPTED = 4


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
    perm = Column(Integer, default=0)
    note = Column(Text, default='')


class Session(Base, TimestampMixin):
    __tablename__ = 'session'

    id = Column(Integer, primary_key=True)
    token = Column(String(S_SHORT), unique=True)

    user_id = Column(Integer, index=True)
    user = relationship('User',
                        foreign_keys=[user_id],
                        primaryjoin='User.id == Session.user_id',
                        backref='sessions')


class UserToken(Base, TimestampMixin):
    __tablename__ = 'user_token'

    id = Column(Integer, primary_key=True)
    token = Column(String(S_SHORT), unique=True)
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

    deleted = Column(Integer, default=0, index=True)

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == JobQueue.owner_id',
                         backref='job_queues')


class JobQueueMember(Base, TimestampMixin):
    __tablename__ = 'job_queue_member'

    id = Column(Integer, primary_key=True)
    perm = Column(Integer)

    deleted = Column(Integer, default=0, index=True)

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

    deleted = Column(Integer, default=0, index=True)

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


class Commit(Base, TimestampMixin):
    __tablename__ = 'commit'

    id = Column(Integer, primary_key=True)

    data = Column(JSON)
    state = Column(Integer, index=True)

    job_id = Column(Integer, index=True)
    job = relationship('Job',
                       foreign_keys=[job_id],
                       primaryjoin='Job.id == Commit.job_id',
                       backref='commits')

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == Commit.owner_id',
                         backref='commits')


class CommitFile(Base, FileMixin):
    __tablename__ = 'commit_file'

    commit_id = Column(Integer, index=True)
    commit = relationship('Commit',
                          foreign_keys=[commit_id],
                          primaryjoin='Commit.id == CommitFile.commit_id',
                          backref='files')
