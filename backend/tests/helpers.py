import hashlib
import os
import uuid

from motor.motor_asyncio import AsyncIOMotorClient


def login(client):
    response = client.post('/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert response.status_code == 200, f'POST /auth/login {response.status_code}: {response.text[:200]}'
    return response.json()


def register_viewer(client, prefix="tscheck-viewer"):
    """Register a fresh public VIEWER account through the real HTTP API."""
    username = f"{prefix}-{uuid.uuid4().hex[:10]}"
    password = "viewerpass123"
    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 200, f"POST /auth/register {response.status_code}: {response.text[:200]}"
    assert response.json()["role"] == "VIEWER"
    return {"username": username, "password": password}


def login_as(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, f"POST /auth/login {response.status_code}: {response.text[:200]}"
    return response.json()


def _hash_password(password: str) -> str:
    """Mirrors routers/auth.py hash_password so direct-DB fixture users authenticate normally."""
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


async def seed_analyst_user(prefix="tscheck-analyst"):
    """Direct-DB fixture: creates an ANALYST test account in the same Mongo the server reads.

    Public /auth/register always forces VIEWER, so this is the only way to reach a writer
    role for isolated fixture data without touching the seeded admin account.
    """
    mongo_url = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
    db_name = os.environ.get("DB_NAME", "app")
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]
    username = f"{prefix}-{uuid.uuid4().hex[:10]}"
    password = "analystpass123"
    user = {
        "id": os.urandom(16).hex(),
        "username": username,
        "role": "ANALYST",
        "password_hash": _hash_password(password),
    }
    await db.users.insert_one(user)
    client.close()
    return {"username": username, "password": password}
