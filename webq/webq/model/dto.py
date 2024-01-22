from pydantic import BaseModel  # pylint: disable=no-name-in-module
from fastapi import HTTPException
from typing import Optional
from enum import IntFlag, IntEnum


def err_unauthorized(msg='unauthorized'):
    return HTTPException(status_code=401, detail=msg)


def err_perm_deny(msg='permission denied'):
    return HTTPException(status_code=403, detail=msg)


def err_not_found(obj_name, obj_id):
    return HTTPException(status_code=404, detail=f'{obj_name} {obj_id} not found')


def err_bad_request(msg='bad request'):
    return HTTPException(status_code=400, detail=msg)


def convert_to_optional(schema):
    return {k: Optional[v] for k, v in schema.__annotations__.items()}


class UserPerm(IntFlag):
    ADMIN = 1

    VIEW_USERS = 1 << 1
    CREATE_USER = 1 << 2
    UPDATE_USER = 1 << 3

    VIEW_JOB_QUEUE = 1 << 4
    CREATE_JOB_QUEUE = 1 << 5
    UPDATE_JOB_QUEUE = 1 << 6


class JobQueuePerm(IntFlag):
    OWNER = 1

    VIEW_JOB = 1 << 1
    CREATE_JOB = 1 << 2
    UPDATE_JOB = 1 << 3
    APPROVE_JOB = 1 << 4  # set job state to ENQUEUED or DEQUEUED

    APPLY_JOB = 1 << 5

    VIEW_COMMIT = 1 << 6
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
    DRAFT = 0
    ABORTED = 1
    SUBMITTED = 2
    # set by job owner or supervisor
    REJECTED = 3
    ACCEPTED = 4


class UserBase(BaseModel):
    name: str
    perm: int = 0
    note: str = ''


class CreateUserReq(UserBase):
    password: str


class UpdateUserReq(BaseModel):
    perm: Optional[int] = None
    note: Optional[str] = None


class ResetPasswordReq(BaseModel):
    new: str
    old: Optional[str]


class UserRes(UserBase):
    class Config:
        from_attributes = True
    id: int


class JobQueueBase(BaseModel):
    name: str
    note: str = ''
    auto_enqueue: bool = True


class CreateJobQueueReq(JobQueueBase):
    pass


class JobQueueRes(JobQueueBase):
    class Config:
        from_attributes = True
    id: int
    owner_id: int


class JobBase(BaseModel):
    flt_str: str = ''
    content: str = ''
    content_type: str = ''
    state: int = 0


class CreateJobReq(JobBase):
    pass


class UpdateJobReq(JobBase):
    pass


class JobRes(JobBase):
    class Config:
        from_attributes = True
    id: int
    queue_id: int
    owner_id: int


class JobFileBase(BaseModel):
    prefix: str
    type: str = ''
    uploaded: bool = False


class CreateJobFileReq(JobFileBase):
    pass


class JobFileRes(JobFileBase):
    class Config:
        from_attributes = True
    id: int
    job_id: int


class ApplyJobsReq(BaseModel):
    flt_str: Optional[str] = None
    limit: int = 1


class CommitBase(BaseModel):
    content: str = ''
    content_type: str = ''
    state: int = 0


class UpdateCommitReq(CommitBase):
    pass


class CommitRes(CommitBase):
    class Config:
        from_attributes = True
    id: int
    job_id: int


class CommitFileBase(BaseModel):
    prefix: str
    type: str = ''


class CreateCommitFileReq(CommitFileBase):
    pass


class CommitFileRes(CommitFileBase):
    class Config:
        from_attributes = True
    id: int
    commit_id: int

