from typing import Optional
from pydantic import BaseModel  # pylint: disable=no-name-in-module
import urllib.parse
import yaml


class FsStorage(BaseModel):
    path: str = './storage'


class S3Storage(BaseModel):
    ...


class Storage(BaseModel):
    fs: Optional[FsStorage] = None
    s3: Optional[S3Storage] = None


class Config(BaseModel):
    base_url: str = 'http://localhost:5000'
    log_level: str = 'info'

    db_url: str = 'sqlite:///./webq.sqlite3'
    storage: Storage = Storage()


class ConfigComponent:
    data: Config

    def __init__(self):
        ...

    def init(self, config_file: str):
        with open(config_file, encoding='utf-8') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
            self.data = Config(**data)

    def get_host_port(self):
        # parse url
        url = urllib.parse.urlparse(self.data.base_url)
        assert url.scheme == 'http', 'only http is supported'
        assert url.hostname, 'hostname is required'
        return url.hostname, url.port or 80


CONFIG_EXAMPLE = '''\
base_url: http://localhost:5000
log_level: info

# url of database, see https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls
# default is sqlite3
db_url: sqlite:///./webq.sqlite3

storage:
  fs:
    path: ./storage
'''
