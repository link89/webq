from fastapi import FastAPI

from .api import auth_apis, user_apis, job_queue_apis

app = FastAPI()

api_version = '/api/v1'

app.include_router(auth_apis, prefix='/api/v1')
app.include_router(user_apis, prefix='/api/v1')
app.include_router(job_queue_apis, prefix='/api/v1')
