from .db import DBComponent
from .config import ConfigComponent
from .service import UserService

db = DBComponent()
config = ConfigComponent()

user_service = UserService()
user_service.db = db
