from fastapi import FastAPI, APIRouter

from .api import auth_apis, user_apis, job_queue_apis

app = FastAPI()

base_router = APIRouter(prefix='/api/v1')
base_router.include_router(auth_apis)
base_router.include_router(user_apis)
base_router.include_router(job_queue_apis)

app.include_router(base_router)
