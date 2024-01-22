from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, OAuth2PasswordRequestForm

from typing import List, Annotated

from .model.db import User
from .model.dto import (
    UserPerm, JobQueuePerm, JobState, CommitState,
    CreateUserReq, UpdateUserReq, UserRes,
    CreateJobQueueReq, JobQueueRes,
    CreateJobReq, UpdateJobReq, JobRes, CreateJobFileReq, JobFileRes,
    ApplyJobsReq,
    UpdateCommitReq, CommitRes, CreateCommitFileReq, CommitFileRes,
)

from .context import get_context, Context
from .log import get_logger

logger = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login", auto_error=False)
api_key_header = APIKeyHeader(name="x-auth-token", auto_error=False)

auth_apis = APIRouter(tags=['Auth'])
user_apis = APIRouter(tags=['User'])
job_queue_apis = APIRouter(tags=['JobQueue'])
other_apis = APIRouter(tags=['Other'])


def get_auth_user(oauth2_token: Annotated[str, Depends(oauth2_scheme)],
            api_key: Annotated[str, Depends(api_key_header)],
            ctx: Annotated[Context, Depends(get_context)],
            ):
    if oauth2_token:
        user = ctx.auth_service.get_user_by_session(oauth2_token)
        if user is not None:
            return user
    if api_key:
        ...  # TODO: implement api key auth

    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


@other_apis.get('/constants.json')
async def get_constant():
    return {
        'user_roles': {
            'default': 0,
            'admin': UserPerm.ADMIN,
        },
        'job_queue_user_roles': {
            'owner': JobQueuePerm.OWNER,
            'worker': JobQueuePerm.APPLY_JOB,
        },
        'job_states': {state.name: state.value for state in JobState},
        'commit_states': {state.name: state.value for state in CommitState},
    }


@auth_apis.get('/me')
async def get_me(me: Annotated[User, Depends(get_auth_user)]) -> UserRes:
    return UserRes.from_orm(me)


@auth_apis.post('/login')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                ctx: Annotated[Context, Depends(get_context)]):
    token = ctx.auth_service.create_session_token(form_data.username, form_data.password)
    if token is None:
        logger.info('login failed: %s', form_data.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {'access_token': token, 'token_type': 'bearer'}


@user_apis.post('/users')
async def create_user(req: CreateUserReq,
                      me: Annotated[User, Depends(get_auth_user)],
                      ctx: Annotated[Context, Depends(get_context)]) -> UserRes:
    user = ctx.user_service.create_user(req, me)
    return UserRes.from_orm(user)

# TODO: pagination
@user_apis.get('/users')
async def get_users(me: Annotated[User, Depends(get_auth_user)],
                    ctx: Annotated[Context, Depends(get_context)]) -> List[UserRes]:
    users = ctx.user_service.get_users(me)
    return [UserRes.from_orm(u) for u in users]


@user_apis.put('/users/{user_id}')
async def update_user(user_id: int,
                      req: UpdateUserReq,
                      me: Annotated[User, Depends(get_auth_user)],
                      ctx: Annotated[Context, Depends(get_context)]) -> UserRes:
    user = ctx.user_service.update_user(user_id, req, me)
    return UserRes.from_orm(user)


@user_apis.delete('/users/{user_id}')
async def delete_user(user_id: int,
                      me: Annotated[User, Depends(get_auth_user)],
                      ctx: Annotated[Context, Depends(get_context)]):
    ctx.user_service.delete_user(user_id, me)


@job_queue_apis.post('/job-queues')
async def create_job_queue(req: CreateJobQueueReq,
                           me: Annotated[User, Depends(get_auth_user)],
                           ctx: Annotated[Context, Depends(get_context)]) -> JobQueueRes:
    job_queue = ctx.job_queue_service.create_queue(req, me)
    return JobQueueRes.from_orm(job_queue)


@job_queue_apis.post('/job-queues/{queue_id}/jobs')
async def create_job(queue_id: int,
                     req: CreateJobReq,
                     me: Annotated[User, Depends(get_auth_user)],
                     ctx: Annotated[Context, Depends(get_context)]) -> JobRes:
    job = ctx.job_queue_service.create_job(queue_id, req, me)
    return JobRes.from_orm(job)

@job_queue_apis.get('/job-queues/{queue_id}/jobs')
async def get_jobs(queue_id: int,
                   me: Annotated[User, Depends(get_auth_user)],
                   ctx: Annotated[Context, Depends(get_context)]) -> List[JobRes]:
    jobs = ctx.job_queue_service.get_jobs(queue_id, me)
    return [JobRes.from_orm(j) for j in jobs]


@job_queue_apis.get('/job-queues/{queue_id}/jobs/{job_id}')
async def get_job(queue_id: int,
                  job_id: int,
                  me: Annotated[User, Depends(get_auth_user)],
                  ctx: Annotated[Context, Depends(get_context)]) -> JobRes:
    job = ctx.job_queue_service.get_job(job_id, me, queue_id=queue_id)
    return JobRes.from_orm(job)


@job_queue_apis.put('/job-queues/{queue_id}/jobs/{job_id}')
async def update_job(queue_id: int,
                     job_id: int,
                     req: UpdateJobReq,
                     me: Annotated[User, Depends(get_auth_user)],
                     ctx: Annotated[Context, Depends(get_context)]) -> JobRes:
    job = ctx.job_queue_service.update_job(job_id, req, me, queue_id=queue_id)
    return JobRes.from_orm(job)


@job_queue_apis.delete('/job-queues/{queue_id}/jobs/{job_id}')
async def delete_job(queue_id: int,
                     job_id: int,
                     me: Annotated[User, Depends(get_auth_user)],
                     ctx: Annotated[Context, Depends(get_context)]):
    ctx.job_queue_service.delete_job(job_id, me, queue_id=queue_id)


@job_queue_apis.post('/job-queues/{queue_id}/jobs/{job_id}/files')
async def create_job_file(queue_id: int,
                          job_id: int,
                          req: CreateJobFileReq,
                          me: Annotated[User, Depends(get_auth_user)],
                          ctx: Annotated[Context, Depends(get_context)]) -> JobFileRes:
    job_file = ctx.job_queue_service.create_job_file(job_id, req, me, queue_id=queue_id)
    return JobFileRes.from_orm(job_file)


@job_queue_apis.post('/job-queues/{queue_id}/jobs/{job_id}/files/{file_id}/upload')
async def upload_job_file(queue_id: int,
                          job_id: int,
                          file_id: int,
                          file: Annotated[UploadFile, File()],
                          me: Annotated[User, Depends(get_auth_user)],
                          ctx: Annotated[Context, Depends(get_context)]) -> JobFileRes:
    job_file = await ctx.job_queue_service.upload_job_file(file_id, file, me,
                                                           queue_id=queue_id, job_id=job_id)
    return JobFileRes.from_orm(job_file)


@job_queue_apis.get('/job-queues/{queue_id}/jobs/{job_id}/files/{file_id}/download')
async def download_job_file(queue_id: int,
                            job_id: int,
                            file_id: int,
                            me: Annotated[User, Depends(get_auth_user)],
                            ctx: Annotated[Context, Depends(get_context)]):
    url, content = await ctx.job_queue_service.download_job_file(file_id, me,
                                                                queue_id=queue_id, job_id=job_id)
    if url is not None:
        return RedirectResponse(url=url)
    else:
        return Response(content=content)  # FIXME: use StreamingResponse for better performance


@job_queue_apis.post('/job-queues/{queue_id}/apply-jobs')
async def apply_jobs(queue_id: int,
                     req: ApplyJobsReq,
                     me: Annotated[User, Depends(get_auth_user)],
                     ctx: Annotated[Context, Depends(get_context)]) -> List[CommitRes]:
    commits = ctx.job_queue_service.apply_jobs(queue_id, req, me)
    return [CommitRes.from_orm(c) for c in commits]


@job_queue_apis.put('/job-queues/{queue_id}/jobs/{job_id}/commits/{commit_id}')
async def update_commit(queue_id: int,
                        job_id: int,
                        commit_id: int,
                        req: UpdateCommitReq,
                        me: Annotated[User, Depends(get_auth_user)],
                        ctx: Annotated[Context, Depends(get_context)]) -> CommitRes:
    commit = ctx.job_queue_service.update_commit(commit_id, req, me,
                                                 queue_id=queue_id, job_id=job_id)
    return CommitRes.from_orm(commit)

@job_queue_apis.post('/job-queues/{queue_id}/jobs/{job_id}/commits/{commit_id}/files')
async def create_commit_file(queue_id: int,
                             job_id: int,
                             commit_id: int,
                             req: CreateCommitFileReq,
                             me: Annotated[User, Depends(get_auth_user)],
                             ctx: Annotated[Context, Depends(get_context)]) -> CommitFileRes:
    commit_file = ctx.job_queue_service.create_commit_file(commit_id, req, me,
                                                           queue_id=queue_id, job_id=job_id)
    return CommitFileRes.from_orm(commit_file)

@job_queue_apis.post('/job-queues/{queue_id}/jobs/{job_id}/commits/{commit_id}/files/{file_id}/upload')
async def upload_commit_file(queue_id: int,
                             job_id: int,
                             commit_id: int,
                             file_id: int,
                             file: Annotated[UploadFile, File()],
                             me: Annotated[User, Depends(get_auth_user)],
                             ctx: Annotated[Context, Depends(get_context)]) -> CommitFileRes:
    commit_file = await ctx.job_queue_service.upload_commit_file(file_id, file, me,
                                                                 queue_id=queue_id, job_id=job_id, commit_id=commit_id)
    return CommitFileRes.from_orm(commit_file)


@job_queue_apis.get('/job-queues/{queue_id}/jobs/{job_id}/commits/{commit_id}/files/{file_id}/download')
async def download_commit_file(queue_id: int,
                               job_id: int,
                               commit_id: int,
                               file_id: int,
                               me: Annotated[User, Depends(get_auth_user)],
                               ctx: Annotated[Context, Depends(get_context)]):
    url, content = await ctx.job_queue_service.download_commit_file(file_id, me,
                                                                    queue_id=queue_id, job_id=job_id, commit_id=commit_id)
    # redirect if url is not None, otherwise return content
    if url is not None:
        return RedirectResponse(url=url)
    else:
        return Response(content=content)
