from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, OAuth2PasswordRequestForm

from typing import List, Annotated

from .model.db import User
from .model.dto import (
    CreateUserReq, UserRes,
    CreateJobQueueReq, JobQueueRes,
)

from .context import get_context, Context
from .log import get_logger

logger = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login", auto_error=False)
api_key_header = APIKeyHeader(name="x-auth-token", auto_error=False)

auth_apis = APIRouter(tags=['Auth'])
user_apis = APIRouter(tags=['User'])
job_queue_apis = APIRouter(tags=['JobQueue'])


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


@job_queue_apis.post('/job-queues')
async def create_job_queue(req: CreateJobQueueReq,
                           me: Annotated[User, Depends(get_auth_user)],
                           ctx: Annotated[Context, Depends(get_context)]):
    job_queue = ctx.job_queue_service.create_queue(req, me)
    return JobQueueRes.from_orm(job_queue)

