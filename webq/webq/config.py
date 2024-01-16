from typing import Optional
from pydantic import BaseModel  # type: ignore
import yaml


class FsStorage(BaseModel):
    path: str = './storage'


class S3Storage(BaseModel):
    ...


class Storage(BaseModel):
    fs: Optional[FsStorage] = None
    s3: Optional[S3Storage] = None


class Config(BaseModel):
    host: str = 'localhost'
    port: int = 5000

    db_url: str = 'sqlite:///./webq.sqlite3'
    storage: Storage = Storage()


class ConfigComponent:
    config: Config

    def __init__(self):
        ...

    def init(self, config_file: str):
        with open(config_file, encoding='utf-8') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
            self.config = Config(**data)
