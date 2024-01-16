from .db import DBComponent
from .config import ConfigComponent
from .service import UserService, AuthService


db = DBComponent()
config = ConfigComponent()

user_service = UserService()
user_service.db = db

auth_service = AuthService()
auth_service.db = db


class Context:
    db: DBComponent
    config: ConfigComponent
    auth_service: AuthService
    user_service: UserService


ctx = Context()

ctx.db = db
ctx.config = config
ctx.auth_service = auth_service
ctx.user_service = user_service


def get_context():
    return ctx
