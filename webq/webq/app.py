from fastapi import FastAPI, APIRouter

from .api import auth_apis, user_apis, job_queue_apis, other_apis

app = FastAPI()

router = APIRouter(prefix='/api/v1')
router.include_router(auth_apis)
router.include_router(user_apis)
router.include_router(job_queue_apis)
router.include_router(other_apis)

app.include_router(router)
