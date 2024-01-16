from .db import DBComponent
from .config import ConfigComponent
from .service import AuthService, UserService, JobQueueService

# instantiate and wire up services
db = DBComponent()
config = ConfigComponent()

auth_service = AuthService()
auth_service.db = db

user_service = UserService()
user_service.db = db

job_queue_service = JobQueueService()
job_queue_service.db = db


# simplify injection
class Context:
    db: DBComponent
    config: ConfigComponent
    auth_service: AuthService
    user_service: UserService
    job_queue_service: JobQueueService


ctx = Context()

ctx.db = db
ctx.config = config
ctx.auth_service = auth_service
ctx.user_service = user_service
ctx.job_queue_service = job_queue_service


def get_context():
    return ctx
