from fastapi import FastAPI

from .api import ep_users

app = FastAPI()

app.include_router(ep_users, prefix='/api/v1')
