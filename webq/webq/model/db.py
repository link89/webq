from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, UniqueConstraint
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

    VIEW_USERS = 1 << 1
    CREATE_USER = 1 << 2
    UPDATE_USER = 1 << 3

    VIEW_JOB_QUEUES = 1 << 4
    CREATE_JOB_QUEUE = 1 << 5
    UPDATE_JOB_QUEUE = 1 << 6


class JobQueuePerm(IntFlag):
    OWNER = 1

    VIEW_JOBS = 1 << 1
    CREATE_JOB = 1 << 2
    UPDATE_JOB = 1 << 3
    APPROVE_JOB = 1 << 4  # set job state to ENQUEUED or DEQUEUED

    APPLY_JOB = 1 << 5

    VIEW_COMMITS = 1 << 6
    CREATE_COMMIT = 1 << 7
    UPDATE_COMMIT = 1 << 8
    APPROVE_COMMIT = 1 << 9  # set commit state to ACCEPTED or REJECTED


class JobState(IntEnum):
    # set by crowdsourcer
    DRAFT = 0
    SUBMITTED = 1
    # set by owner or supervisor
    ENQUEUED = 2
    DEQUEUED = 3


class CommitState(IntEnum):
    # set by worker
    PENDING = 0
    ABORTED = 1
    SUBMITTED = 2
    # set by job owner or supervisor
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
    name = Column(String(S_SHORT), unique=True)
    password = Column(String(S_SHORT))
    perm = Column(Integer, default=0)
    note = Column(Text, default='')
    deleted = Column(Boolean, default=0, index=True)


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
    auto_enqueue = Column(Boolean, default=1)
    deleted = Column(Boolean, default=0, index=True)

    owner_id = Column(Integer, index=True)
    owner = relationship('User',
                         foreign_keys=[owner_id],
                         primaryjoin='User.id == JobQueue.owner_id',
                         backref='job_queues')


class JobQueueMember(Base, TimestampMixin):
    __tablename__ = 'job_queue_member'

    id = Column(Integer, primary_key=True)
    perm = Column(Integer)

    deleted = Column(Boolean, default=0, index=True)

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

    # jobq_id and user_id must be union unique
    __table_args__ = (
        UniqueConstraint('jobq_id', 'user_id'),
    )


class Job(Base, TimestampMixin):
    __tablename__ = 'job'
    id = Column(Integer, primary_key=True)

    flt_str = Column(String, index=True)

    content = Column(Text)
    content_type = Column(String(S_SHORT))

    state = Column(Integer, index=True)
    deleted = Column(Boolean, default=0, index=True)

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
    __table_args__ = (
        UniqueConstraint('job_id', 'prefix'),
    )


class Commit(Base, TimestampMixin):
    __tablename__ = 'commit'

    id = Column(Integer, primary_key=True)
    state = Column(Integer, index=True)

    content = Column(Text)
    content_type = Column(String(S_SHORT))

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
    __table_args__ = (
        UniqueConstraint('commit_id', 'prefix'),
    )
