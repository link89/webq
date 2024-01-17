from .db import DBComponent
from .config import ConfigComponent
from .service import AuthService, UserService, JobQueueService
from .storage import FsStorage

class Context:
    inited: bool = False
    db: DBComponent
    config: ConfigComponent
    auth_service: AuthService
    user_service: UserService
    job_queue_service: JobQueueService

_ctx = Context()

def init(c: str):
    if _ctx.inited:
        return
    config = ConfigComponent()
    config.init(c)

    db = DBComponent()
    db.init(config.data.db_url)

    if config.data.storage.fs:
        storage = FsStorage()
        storage.init(config.data.storage.fs.path)
    elif config.data.storage.s3:
        raise NotImplementedError()
    else:
        raise ValueError('storage not configured')

    auth_service = AuthService()
    auth_service.db = db

    user_service = UserService()
    user_service.db = db

    job_queue_service = JobQueueService()
    job_queue_service.db = db
    job_queue_service.storage = storage

    # init context
    _ctx.db = db
    _ctx.config = config
    _ctx.auth_service = auth_service
    _ctx.user_service = user_service
    _ctx.job_queue_service = job_queue_service

    _ctx.inited = True


def get_context():
    return _ctx
