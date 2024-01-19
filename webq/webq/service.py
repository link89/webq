from fastapi import UploadFile
from typing import Optional, ContextManager
from datetime import datetime
import bcrypt
import secrets
import hashlib
import os
import re


from .model.db import (
    User, Session,
    JobQueue, JobQueueMember,
    Job, JobFile,
    Commit, CommitFile,
)
from .model.dto import (
    UserPerm, JobQueuePerm, JobState, CommitState,
    CreateUserReq, UpdateUserReq,
    CreateJobQueueReq,
    CreateJobReq,
    CreateJobFileReq,
    ApplyJobsReq,
    err_perm_deny, err_not_found, err_bad_request,
)

from .db import DBComponent
from .storage import IStorage
from .log import get_logger

logger = get_logger(__name__)

# TODO: refactor the permission handling in service layer
# TODO: investigate permission management framework like oso

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

    def get_session(self) -> ContextManager:
        return self.db.get_db_session()


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

    def _query_user(self, session, user_id: int):
        return session.query(User).filter_by(id=user_id, deleted=0)

    def _query_users(self, session):
        return session.query(User).filter_by(deleted=0)


class JobQueueService(DbService):
    storage: IStorage

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

    def create_job(self, queue_id: int, req: CreateJobReq, me: User):
        with self.get_session() as session:
            # ensure queue exists
            queue: JobQueue = self._query_queue(session, queue_id).first()
            if queue is None:
                raise err_not_found('queue', queue_id)
            # ensure user has permission
            perm = self._get_queue_perm(session, queue, me)
            if not has_perm(perm, [JobQueuePerm.OWNER, JobQueuePerm.CREATE_JOB]):
                raise err_perm_deny()
            is_approver = has_perm(perm, [JobQueuePerm.OWNER, JobQueuePerm.APPROVE_JOB])
            # ensure job state is valid
            if req.state not in self._next_job_states(None, is_approver):
                raise err_bad_request(f'invalid state {req.state}')
            # auto enqueue
            req.state = self._auto_enqueue(req.state, queue.auto_enqueue)
            # create job
            job = Job()
            job.flt_str = req.flt_str
            job.content = req.content
            job.content_type = req.content_type
            job.state = req.state
            job.queue_id = queue_id
            job.owner_id = me.id
            session.add(job)
            session.commit()
            session.refresh(job)
            return job


    def get_job(self, job_id: int, me: User, queue_id: Optional[int] = None):
        with self.get_session() as session:
            # ensure queue and job exist
            job = self._get_job(session, job_id, queue_id)
            # ensure user has permission
            queue_perm = self._get_queue_perm(session, job.queue, me)
            if job.owner_id != me.id \
                    and not has_perm(queue_perm, [JobQueuePerm.OWNER, JobQueuePerm.VIEW_JOB]) \
                    and session.query(Commit).filter_by(job_id=job_id, owner_id=me.id).first() is None:
                raise err_perm_deny()
            return job

    def update_job(self, job_id: int, req: CreateJobReq, me: User, queue_id: Optional[int] = None):
        with self.get_session() as session:
            # ensure queue and job exist
            job = self._get_job(session, job_id, queue_id)
            # ensure user has permission
            queue_perm = self._get_queue_perm(session, job.queue, me)
            if job.owner_id != me.id \
                    and not has_perm(queue_perm, [JobQueuePerm.OWNER, JobQueuePerm.UPDATE_JOB]):
                raise err_perm_deny()
            is_approver = has_perm(queue_perm, [JobQueuePerm.OWNER, JobQueuePerm.APPROVE_JOB])
            # if current state is not draft, only allow state change
            req_dict = req.dict(exclude_unset=True)
            if job.state != JobState.DRAFT:
                if 'state' not in req_dict or len(req_dict) != 1:
                    raise err_bad_request('only state can be updated for non-draft job')
            # ensure new job state is valid
            if 'state' in req_dict:
                if req_dict['state'] not in self._next_job_states(job.state, is_approver):
                    raise err_bad_request(f'invalid state {req.state}')
                req_dict['state'] = self._auto_enqueue(req_dict['state'], job.queue.auto_enqueue)
            # update job
            self._query_job(session, job_id).update(req_dict)
            session.commit()
            session.refresh(job)
            return job

    def create_job_file(self, job_id: int, req: CreateJobFileReq, me: User, queue_id: Optional[int] = None):
        req.prefix = self._formalize_prefix(req.prefix)
        with self.get_session() as session:
            # ensure job and queue exist
            job = self._get_job(session, job_id, queue_id)
            # ensure job state is valid
            if job.state != JobState.DRAFT:
                raise err_bad_request(f'forbid file create as job {job_id} is not in draft state')
            # ensure user has permission
            queue_perm = self._get_queue_perm(session, job.queue, me)
            if job.owner_id != me.id \
                    and not has_perm(queue_perm, [JobQueuePerm.OWNER, JobQueuePerm.UPDATE_JOB]):
                raise err_perm_deny()

            job_file = JobFile()
            job_file.prefix = req.prefix
            job_file.type = req.content_type
            job_file.job_id = job_id

            session.add(job_file)
            session.commit()
            session.refresh(job_file)
            return job_file

    # FIXME : this method should be async or else it will block the event loop
    async def upload_job_file(self, file_id: int, file: UploadFile, me: User, job_id: int, queue_id: int):
        if not self.storage.is_local():
            raise err_bad_request('upload is not supported for non-local storage')

        with self.get_session() as session:
            job_file = self._get_job_file(session, file_id, job_id=job_id, queue_id=queue_id)
            # ensure job state is valid
            if job_file.job.state != JobState.DRAFT:
                raise err_bad_request(f'forbid file upload: state of job {job_id} {JobState(job_file.job.state)} is not DRAFT')
            # ensure user has permission
            queue_perm = self._get_queue_perm(session, job_file.job.queue, me)
            if job_file.job.owner_id != me.id \
                    and not has_perm(queue_perm, [JobQueuePerm.OWNER, JobQueuePerm.UPDATE_JOB]):
                raise err_perm_deny()
            # save file
            prefix = self._get_full_prefix(job_file.prefix, queue_id=queue_id, job_id=job_id)
            # FIXME: use stream pipe to create file
            await self.storage.create_file(prefix, await file.read())
            if job_file.type is None:
                job_file.type = file.content_type
            job_file.uploaded = 1
            session.commit()
            session.refresh(job_file)
            return job_file


    def get_job_file_upload_url(self):
        if not self.storage.is_local():
            raise err_bad_request('upload directly for non-local storage')
        # TODO: generate a url to upload file




    def dowload_job_file(self, job_id: int, file_id: int, me: User, queue_id: Optional[int] = None):
        if self.storage.is_local():
            ...  # TODO: get bytes object from storage
        else:
            ...  # TODO: get download url from storage and 302 redirect

    def apply_jobs(self, queue_id: int, req: ApplyJobsReq, me: User):
        with self.get_session() as session:
            # ensure queue exists
            queue: JobQueue = self._query_queue(session, queue_id).first()
            if queue is None:
                raise err_not_found('queue', queue_id)
            # ensure user has permission
            perm = self._get_queue_perm(session, queue, me)
            if not has_perm(perm, [JobQueuePerm.OWNER, JobQueuePerm.APPLY_JOB]):
                raise err_perm_deny()
            # query qualified jobs
            query = self._query_jobs(session, queue_id).filter_by(state=JobState.ENQUEUED.value)
            ## if flt_str is provided, use LIKE clause to match flt_str
            flt_str = req.flt_str
            if flt_str is not None:
                if flt_str.startswith('!'):
                    query = query.filter(Job.flt_str.notlike(flt_str[1:]))
                else:
                    query = query.filter(Job.flt_str.like(flt_str))
            ## get jobs
            jobs = query.limit(req.limit).all()
            commits = []
            for job in jobs:
                # dequeue job
                job.state = JobState.DEQUEUED.value
                # create commit
                commit = Commit()
                commit.job_id = job.id
                commit.owner_id = me.id
                commit.state = CommitState.DRAFT.value
                session.add(commit)
                commits.append(commit)
            session.commit()
            for commit in commits:
                session.refresh(commit)
            return commits

    def update_commit(self, queue_id: int, job_id: int, commit_id: int, req: CreateJobReq, me: User):
        ...

    def delete_commit(self):
        ...

    def create_commit_file(self):
        ...

    def upload_commit_file(self):
        ...


    def _get_job_file(self, session, file_id: int, job_id: Optional[int], queue_id: Optional[int]) -> JobFile:
        job_file: JobFile = session.query(JobFile).filter_by(id=file_id).first()
        if job_file is None:
            raise err_not_found('job_file', file_id)
        if job_id is not None and job_file.job_id != job_id:
            raise err_bad_request(f'file {file_id} does not belong to job {job_id}')
        if queue_id is not None and job_file.job.queue_id != queue_id:
            raise err_bad_request(f'job {job_file.job_id} does not belong to queue {queue_id}')
        return job_file

    def _get_job(self, session, job_id: int, queue_id: Optional[int]) -> Job:
        job: Job = self._query_job(session, job_id).first()
        if job is None:
            raise err_not_found('job', job_id)
        if queue_id is not None and job.queue_id != queue_id:
            raise err_bad_request(f'job {job_id} does not belong to queue {queue_id}')
        return job

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

    def _query_queue(self, session, queue_id: int):
        return session.query(JobQueue).filter_by(id=queue_id, deleted=0)

    def _query_queues(self, session):
        return session.query(JobQueue).filter_by(deleted=0)

    def _query_job(self, session, job_id: int):
        return session.query(Job).filter_by(id=job_id, deleted=0)

    def _query_jobs(self, session, queue_id: int):
        return session.query(Job).filter_by(queue_id=queue_id, deleted=0)

    def _next_job_states(self, state: Optional[int], is_approver: bool = False):
        """
        validate if a job state transition is allowed
        DRAFT -> READY -> ENQUEUED or DEQUEUED
        """
        if state in [None, JobState.DRAFT]:
            if is_approver:
                return [JobState.DRAFT, JobState.SUBMITTED, JobState.ENQUEUED, JobState.DEQUEUED]
            return [JobState.DRAFT, JobState.SUBMITTED]
        return [JobState.ENQUEUED, JobState.DEQUEUED]

    def _auto_enqueue(self, state: int, auto_enqueue: bool):
        if state == JobState.SUBMITTED and auto_enqueue:
            return JobState.ENQUEUED.value
        return state

    def _get_full_prefix(self, prefix: str, queue_id: int, job_id: int, commit_id: Optional[int] = None):
        path = f'job-queue/{queue_id}/job/{job_id}'
        if commit_id is not None:
            path += f'/commit/{commit_id}'
        return os.path.join(path, prefix)

    def _formalize_prefix(self, prefix: str):
        prefix = prefix.strip(' /')
        if not prefix:
            raise err_bad_request(f'invalid prefix {prefix}: empty path')
        for token in prefix.split('/'):
            if not token.strip(' .'):
                raise err_bad_request(f'invalid token in prefix: {token}')
            if not re.fullmatch(r'[a-zA-Z0-9_\.\-]+', token):
                raise err_bad_request(f'invalid token in prefix: {token}')
        return prefix
