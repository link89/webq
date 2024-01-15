from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header = APIKeyHeader(name="x-auth-token", auto_error=False)


def get_current_user(oauth2_token: str = Depends(oauth2_scheme),
                     api_key: str = Depends(api_key_header)):

    return oauth2_token, api_key


