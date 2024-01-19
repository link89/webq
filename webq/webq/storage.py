from pydantic import BaseModel # pylint: disable=no-name-in-module
import os


class IStorage:

    def is_local(self) -> bool:
        raise NotImplementedError()

    async def create_file(self, prefix: str, content: bytes, overwrite: bool = False):
        raise NotImplementedError()

    def get_file(self, prefix: str) -> bytes:
        raise NotImplementedError()

    async def get_upload_url(self, prefix: str):
        raise NotImplementedError()


class FsStorage(IStorage):
    path: str

    def init(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def is_local(self) -> bool:
        return True

    # FIXME: use stream pipe to create file
    async def create_file(self, prefix: str, content: bytes, overwrite: bool = False):
        path = os.path.join(self.path, prefix)

        basedir = os.path.dirname(path)
        os.makedirs(basedir, exist_ok=True)
        if not overwrite and os.path.exists(path):
            raise FileExistsError(path)
        with open(path, 'wb') as f:
            f.write(content)

    def get_file(self, prefix: str) -> bytes:
        path = os.path.join(self.path, prefix)
        with open(path, 'rb') as f:
            return f.read()


class S3Config(BaseModel):
    access_key: str
    secret_key: str
    endpoint_url: str
    bucket: str


class S3Storage(IStorage):
    def is_local(self) -> bool:
        return False
