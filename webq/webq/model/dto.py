from pydantic import BaseModel


class CreateUserReq(BaseModel):
    username: str
    password: str
    permission: int = 0


class UserRes(BaseModel):
    id: int
    username: str
    permission: int = 0
