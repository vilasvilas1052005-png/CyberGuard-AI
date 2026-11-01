from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, APIRouter
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from routers.auth import router as auth_router
from routers.soc import router as soc_router


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
from lib.db import client, db


# Startup runs before the yield, shutdown after it. Add your own setup/teardown here.
@asynccontextmanager
async def lifespan(app: FastAPI):
    from routers.auth import hash_password
    if not await db.users.find_one({"username": "admin"}):
        await db.users.insert_one({"id": "dev-admin", "username": "admin", "role": "ADMIN", "password_hash": hash_password("admin123"), "created_at": datetime.now(timezone.utc)})
    yield
    client.close()


# Create the main app without a prefix
app = FastAPI(lifespan=lifespan)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


"""Application bootstrap; domain routes live in routers/auth.py and routers/soc.py."""

# Add your routes to the router instead of directly to app
api_router.include_router(auth_router)
api_router.include_router(soc_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app.include_router(api_router)
