from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
from typing import Dict, Optional

load_dotenv()

# Validate SECRET_KEY
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

SECRET_REFRESH_KEY = os.getenv("SECRET_REFRESH_KEY")
if not SECRET_REFRESH_KEY:
    raise ValueError("SECRET_REFRESH_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))  # Default 15 minutes
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))      # Default 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password using bcrypt."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a plain password using bcrypt."""
    return pwd_context.hash(password)

def create_access_token(data: Dict) -> str:
    """Create a JWT access token with expiration and issued-at times."""
    to_encode = data.copy()
    issued_at = datetime.now(timezone.utc)
    expire = issued_at + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": issued_at, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: Dict) -> str:
    """Create a JWT refresh token with expiration and issued-at times."""
    to_encode = data.copy()
    issued_at = datetime.now(timezone.utc)
    expire = issued_at + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": issued_at, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_REFRESH_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[Dict]:
    """Decode a JWT access token and return its payload, or None if invalid."""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": True}
        )
        return payload
    except JWTError as e:
        print(f"Access token decoding error: {e}")
        return None

def decode_refresh_token(token: str) -> Optional[Dict]:
    """Decode a JWT refresh token and return its payload, or None if invalid."""
    try:
        payload = jwt.decode(
            token,
            SECRET_REFRESH_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": True}
        )
        return payload
    except JWTError as e:
        print(f"Refresh token decoding error: {e}")
        return None