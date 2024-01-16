from fastapi import HTTPException
from datetime import datetime
import bcrypt
import secrets
import hashlib

from .db import DBComponent
from .model.db import User, UserToken, UserPerm, Session
from .model.dto import CreateUserReq, UpdateUserReq

# TODO: use either monad for error handling


def has_perm(perm, perm_list):
    for p in perm_list:
        if perm & p:
            return True
    return False


def gen_token():
    return secrets.token_urlsafe(32)


def hash_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()


def err_unauthorized(msg='unauthorized'):
    return HTTPException(status_code=401, detail=msg)


def err_perm_deny(msg='permission denied'):
    return HTTPException(status_code=403, detail=msg)


def err_not_found(obj_name, obj_id):
    return HTTPException(status_code=404, detail=f'{obj_name} {obj_id} not found')


class Service:
    ...


class DbService(Service):

    db: DBComponent

    def get_session(self):
        return self.db.get_db_session()

    def _query_user(self, session, user_id: int):
        return session.query(User).filter_by(id=user_id, deleted=0)

    def _query_users(self, session):
        return session.query(User).filter_by(deleted=0)


# TODO: handle session expire
class AuthService(DbService):

    def create_session_token(self, username: str, password: str):
        with self.get_session() as session:
            user = session.query(User).filter_by(
                username=username, deleted=0).first()
            if user is None:
                return None
            if not bcrypt.checkpw(password.encode(), user.password.encode()):
                return None
            token = gen_token()
            session_token = Session()
            session_token.token = hash_token(token)
            session_token.user_id = user.id
            session.add(session_token)
            session.commit()
            return str(session_token.id) + '-' +  token

    def get_user_by_session(self, token: str):
        sid, token = token.split('-', maxsplit=1)
        sid = int(sid)
        token = hash_token(token)
        with self.get_session() as session:
            session_token = session.query(Session).filter_by(
                id=sid, token=token).first()
            if session_token is None:
                return None
            session.query(Session).filter_by(id=sid).update({'updated_at': datetime.now()})
            session.commit()
            return session_token.user


class UserService(DbService):

    def get_user(self, user_id: int, me: User):
        if me.id != user_id and not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.VIEW_USERS]):
            raise err_perm_deny()
        with self.get_session() as session:
            return self._query_user(session, user_id).first()

    def get_users(self, me: User):
        if not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.VIEW_USERS]):
            return [me]
        with self.get_session() as session:
            return self._query_users(session).all()

    def create_user(self, req: CreateUserReq, me: User):
        if not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.CREATE_USER]):
            raise err_perm_deny()

        # TODO: password strength check
        with self.get_session() as session:
            user = User()
            user.username = req.username
            user.note = req.note
            user.perm = req.perm
            user.password = bcrypt.hashpw(
                req.password.encode(), bcrypt.gensalt()).decode()
            session.add(user)
            session.commit()
            return user

    def update_user(self, user_id: int, req: UpdateUserReq, me: User):
        if me.id != user_id and not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.UPDATE_USER]):
            raise err_perm_deny()

        req_dict = req.dict(exclude_unset=True)
        if 'password' in req_dict:
            req_dict['password'] = bcrypt.hashpw(
                req_dict['password'].encode(), bcrypt.gensalt())

        with self.get_session() as session:
            user = self._query_user(session, user_id).first()
            if user is None:
                raise err_not_found('user', user_id)
            self._query_user(session, user_id).update(req_dict)
            session.commit()
            return self._query_user(session, user_id).first()

    def delete_user(self, user_id: int, me: User):
        if me.id != user_id and not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.UPDATE_USER]):
            raise err_perm_deny()

        with self.get_session() as session:
            self._query_user(session, user_id).update({'deleted': 1})
            session.commit()


