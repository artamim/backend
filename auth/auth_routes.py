from fastapi import APIRouter, HTTPException, Depends, status, Response, FastAPI, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import EmailStr
from models import UserRegister, UserLogin, Token
from database import users_collection
from auth.auth import verify_password, get_password_hash, create_access_token, create_refresh_token, decode_token, decode_refresh_token
from typing import Optional
import os
from urllib.parse import urlparse

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def is_same_origin(request: Request) -> bool:
    """Check if the request is from the same origin as the server"""
    host = request.headers.get("host", "")
    origin = request.headers.get("origin", "")
    
    if not origin:
        return False
    
    # Extract hostname from origin, handling ports and paths
    parsed_origin = urlparse(origin)
    origin_host = parsed_origin.hostname
    return host == origin_host

def set_auth_cookies(response: Response, access_token: str, refresh_token: str, request: Request):
    """Set authentication cookies with appropriate SameSite and Secure policies"""
    is_cross_origin = not is_same_origin(request)
    
    # Use secure=True in production for better security
    cookie_settings = {
        "httponly": True,
        "secure": "true",  # Secure cookies in production
        "path": "/",
        "samesite": "none" if is_cross_origin else "lax"  # None for cross-origin, Lax for same-origin
    }
    
    response.set_cookie(
        key="accessToken",
        value=access_token,
        max_age=15 * 60,  # 15 minutes
        **cookie_settings
    )
    
    response.set_cookie(
        key="refreshToken",
        value=refresh_token,
        max_age=7 * 24 * 60 * 60,  # 7 days
        **cookie_settings
    )

@router.post("/register", response_model=Token)
async def register(user: UserRegister, response: Response, request: Request):
    
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    user_dict = {
        "email": user.email,
        "hashed_password": hashed_password,
        "name": user.name
    }
    users_collection.insert_one(user_dict)
    
    user_data = {"sub": user.email, "name": user.name}
    access_token = create_access_token(user_data)
    refresh_token = create_refresh_token(user_data)
    
    set_auth_cookies(response, access_token, refresh_token, request)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
async def login(user: UserLogin, response: Response, request: Request):
    
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_data = {
        "sub": db_user["email"],
        "name": db_user.get("name", "Unknown")
    }
    access_token = create_access_token(user_data)
    refresh_token = create_refresh_token(user_data)
    
    set_auth_cookies(response, access_token, refresh_token, request)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/refresh", response_model=dict)
async def refresh_token(refresh_token: str, response: Response, request: Request):
    payload = decode_refresh_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    email = payload.get("sub")
    name = payload.get("name", "Unknown")
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = {
        "sub": db_user["email"],
        "name": db_user.get("name", "Unknown")
    }
    access_token = create_access_token(user_data)
    new_refresh_token = create_refresh_token(user_data)
    
    set_auth_cookies(response, access_token, new_refresh_token, request)
    
    return {
        "message": "Token refreshed",
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "user": {
            "id": str(db_user["_id"]),
            "name": user_data["name"],
            "email": user_data["sub"]
        }
    }

@router.get("/me")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid access token")
    
    user = users_collection.find_one({"email": payload.get("sub")})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "name": user.get("name", "Unknown"),
        "email": user.get("email")
    }