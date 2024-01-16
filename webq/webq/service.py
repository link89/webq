from datetime import datetime
import bcrypt
import secrets
import hashlib

from .model.db import (
    User, UserToken, UserPerm, Session,
    JobQueue, JobQueueMember, JobQueuePerm,
)
from .model.dto import (
    CreateUserReq, UpdateUserReq, UserRes,
    CreateJobQueueReq,
    err_perm_deny, err_not_found,
)

from .db import DBComponent
from .log import get_logger

logger = get_logger(__name__)


def has_perm(perm, perm_list):
    for p in perm_list:
        if perm & p:
            return True
    return False


def gen_token():
    return secrets.token_urlsafe(32)

def hash_password(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def hash_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()


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


class AuthService(DbService):

    def create_session_token(self, name: str, password: str):
        # TODO: handle session expire
        with self.get_session() as session:
            user = session.query(User).filter_by(
                name=name, deleted=0).first()
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
        # TODO: handle malformed token
        sid, token = token.split('-', maxsplit=1)
        sid = int(sid)
        token = hash_token(token)

        with self.get_session() as session:
            session_token = session.query(Session).filter_by(
                id=sid, token=token).first()
            if session_token is None:
                return None
            # refresh session
            session.query(Session).filter_by(id=sid).update({'updated_at': datetime.now()})
            session.commit()
            return session_token.user


class UserService(DbService):

    def create_admin(self):
        username = 'admin'
        password = secrets.token_urlsafe(16)
        with self.get_session() as session:
            # if no admin exists, create one
            if session.query(User).filter_by(name=username).first() is None:
                user = User()
                user.name = 'admin'
                user.password = hash_password(password)
                user.perm = UserPerm.ADMIN
                session.add(user)
                session.commit()
                logger.info('admin created with password: %s', password)
                return user
            else:
                logger.info('admin already exists')

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
            user.name = req.name
            user.note = req.note
            user.perm = req.perm
            user.password = hash_password(req.password)
            session.add(user)
            session.commit()
            session.refresh(user)
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
            session.refresh(user)
            return user

    def delete_user(self, user_id: int, me: User):
        if me.id != user_id and not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.UPDATE_USER]):
            raise err_perm_deny()

        with self.get_session() as session:
            self._query_user(session, user_id).update({'deleted': 1})
            session.commit()


class JobQueueService(DbService):

    def create_queue(self, req: CreateJobQueueReq, me: User):
        if not has_perm(me.perm, [UserPerm.ADMIN, UserPerm.CREATE_JOB_QUEUE]):
           raise err_perm_deny()

        with self.get_session() as session:
            queue = JobQueue()
            queue.name = req.name
            queue.note = req.note
            queue.auto_enqueue = req.auto_enqueue
            queue.owner_id = me.id
            session.add(queue)
            session.commit()
            session.refresh(queue)
            return queue

    def create_job(self, queue_id: int, me: User):
        with self.get_session() as session:
            queue = self._query_queue(session, queue_id).first()
            if queue is None:
                raise err_not_found('queue', queue_id)
            perm = self._get_queue_perm(session, queue, me)
            if not has_perm(perm, [JobQueuePerm.OWNER, JobQueuePerm.CREATE_JOB]):
                raise err_perm_deny()
            # TODO: create queue

    def _get_queue_perm(self, session, queue: JobQueue, me: User) -> int:
        if queue.owner_id == me.id:
            return JobQueuePerm.OWNER.value
        if has_perm(me.perm, [UserPerm.ADMIN]):
            return JobQueuePerm.OWNER.value  # system admin has the same perm as owner
        member = session.query(JobQueueMember).filter_by(
            queue_id=queue.id, user_id=me.id).first()
        if member is not None:
            return member.perm
        return 0

    def _get_queue(self, queue_id: int):
        with self.get_session() as session:
            queue = self._query_queue(session, queue_id).first()
            if queue is None:
                raise err_not_found('queue', queue_id)
            return queue

    def _query_queue(self, session, queue_id: int):
        return session.query(JobQueue).filter_by(id=queue_id, deleted=0)

    def _query_queues(self, session):
        return session.query(JobQueue).filter_by(deleted=0)
