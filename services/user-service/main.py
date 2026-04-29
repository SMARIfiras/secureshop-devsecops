"""
User Service — SecureShop
Responsibilities: Registration, Login, JWT issuance, Profile management
Language: Python 3.12 / FastAPI  |  Port: 8001
"""
import os
import sqlite3
import logging
import uuid
import datetime
from typing import Optional
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
from jose import jwt, JWTError

# ── Configuration ────────────────────────────────────────────────────────────
# SAST NOTE: Bandit B105 — hardcoded default caught here; real value comes from env
SECRET_KEY: str = os.environ.get("JWT_SECRET", "dev-secret-change-me")  # nosec B105
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
DB_PATH: str = os.environ.get("DATABASE_URL", "/data/users.db")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s %(message)s")
logger = logging.getLogger("user-service")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="User Service", version="1.0.0")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# ── Database ──────────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                email           TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                full_name       TEXT,
                role            TEXT DEFAULT 'customer',
                created_at      TEXT NOT NULL
            )
        """)
        # Seed admin for DAST testing
        conn.execute("""
            INSERT OR IGNORE INTO users (id, email, hashed_password, full_name, role, created_at)
            VALUES (?,?,?,?,?,?)
        """, (
            str(uuid.uuid4()), "admin@secureshop.local",
            pwd_context.hash("Admin1234!"), "Workshop Admin", "admin",
            datetime.datetime.utcnow().isoformat(),
        ))
        conn.commit()
    logger.info("DB ready at %s", DB_PATH)


# ── Pydantic Models ───────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    role: str
    created_at: str


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None


# ── JWT Helpers ───────────────────────────────────────────────────────────────
def create_access_token(subject: str, role: str) -> str:
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": subject, "role": role, "exp": expire, "iat": datetime.datetime.utcnow()},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {"service": "user-service", "status": "ok", "version": "1.0.0"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest):
    """Register a new customer account."""
    hashed = pwd_context.hash(req.password)
    user_id = str(uuid.uuid4())
    created_at = datetime.datetime.utcnow().isoformat()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (id,email,hashed_password,full_name,role,created_at) VALUES (?,?,?,?,?,?)",
                (user_id, req.email, hashed, req.full_name, "customer", created_at),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")
    logger.info("New user registered: %s", req.email)
    return {"id": user_id, "email": req.email, "message": "Registered successfully"}


@app.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    """Authenticate and receive a JWT."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (req.email,)).fetchone()
    if not row or not pwd_context.verify(req.password, row["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(subject=row["id"], role=row["role"])
    logger.info("Login: %s", req.email)
    return TokenResponse(access_token=token)


@app.get("/profile", response_model=UserProfile)
def get_profile(payload: dict = Depends(verify_token)):
    """Return the current user's profile."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfile(id=row["id"], email=row["email"], full_name=row["full_name"],
                       role=row["role"], created_at=row["created_at"])


@app.put("/profile")
def update_profile(req: UpdateProfileRequest, payload: dict = Depends(verify_token)):
    """Update allowed profile fields."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET full_name = ? WHERE id = ?",
            (req.full_name, payload["sub"]),
        )
        conn.commit()
    return {"message": "Profile updated"}


@app.get("/users/{user_id}", include_in_schema=False)
def get_user_internal(user_id: str):
    """Internal endpoint — called by other services (not exposed via gateway)."""
    with get_db() as conn:
        row = conn.execute("SELECT id,email,full_name,role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)
