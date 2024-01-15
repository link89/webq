
from .db import DBComponent
from .model.db import User, UserToken, UserPerm



class Service:
    ...


class UserService(Service):

    def __init__(self, db: DBComponent):
        self.db = db

    def get_session(self):
        return self.db.get_db_session()

    def get_user(self, user_id: int, me: User):
        if me and not me.permission & UserPerm.ADMIN and me.id != user_id:
            raise ValueError('no permission')
        with self.get_session() as session:
            return session.query(User).filter_by(id=user_id).first()

    def get_users(self, me: User):
        if me and not me.permission & UserPerm.ADMIN:
            raise ValueError('no permission')
        with self.get_session() as session:
            return session.query(User).all()

    def create_user(self, ):
        ...


