from typing import Optional
from pydantic import BaseModel


class FsStorage(BaseModel):
    path: str = './storage'


class S3Storage(BaseModel):
    ...


class Storage(BaseModel):
    fs: Optional[FsStorage] = None
    s3: Optional[S3Storage] = None


class Setting(BaseModel):
    host: str = 'localhost'
    port: int = 5000

    db_url: str = 'sqlite:///./webq.db'
    storage: Storage = Storage()
