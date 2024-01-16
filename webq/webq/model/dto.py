from typing import Optional
from pydantic import BaseModel  # type: ignore


def convert_to_optional(schema):
    return {k: Optional[v] for k, v in schema.__annotations__.items()}


class UserBase(BaseModel):
    username: str
    perm: int = 0
    note: str = ''


class CreateUserReq(UserBase):
    password: str


class UpdateUserReq(CreateUserReq):
    __annotations__ = convert_to_optional(CreateUserReq)


class UserRes(UserBase):
    id: int

