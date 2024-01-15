from .db import DBComponent
from .service import UserService

db = DBComponent()

user_service = UserService(db)


