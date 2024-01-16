from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader

from typing import Annotated

from .model.db import User
from .model.dto import UserRes
from .context import get_context, Context


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
api_key_header = APIKeyHeader(name="x-auth-token", auto_error=False)

ep_users = APIRouter(tags=['Users'])


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


@ep_users.get('/me')
async def get_me(me: Annotated[User, Depends(get_auth_user)]) -> UserRes:
    return UserRes.from_orm(me)
