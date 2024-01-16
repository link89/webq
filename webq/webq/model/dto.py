from pydantic import BaseModel  # type: ignore
from fastapi import HTTPException
from typing import Optional


def err_unauthorized(msg='unauthorized'):
    return HTTPException(status_code=401, detail=msg)


def err_perm_deny(msg='permission denied'):
    return HTTPException(status_code=403, detail=msg)


def err_not_found(obj_name, obj_id):
    return HTTPException(status_code=404, detail=f'{obj_name} {obj_id} not found')


def convert_to_optional(schema):
    return {k: Optional[v] for k, v in schema.__annotations__.items()}


class UserBase(BaseModel):
    name: str
    perm: int = 0
    note: str = ''


class CreateUserReq(UserBase):
    password: str


class UpdateUserReq(CreateUserReq):
    __annotations__ = convert_to_optional(CreateUserReq)


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
    flt_str: str
    data: dict
    state: int

class CreateJobReq(JobBase):
    pass


class JobRes(JobBase):
    class Config:
        from_attributes = True
    id: int
    jobq_id: int
    owner_id: int