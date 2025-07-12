from fastapi import APIRouter, HTTPException, Depends, status, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import EmailStr
from models import User, Token
from database import users_collection
from auth.auth import verify_password, get_password_hash, create_access_token, create_refresh_token, decode_token
from typing import Optional

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.post("/register", response_model=Token)
async def register(user: User, response: Response):
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    user_dict = {
        "email": user.email,
        "hashed_password": hashed_password,
        "name": user.name if user.name else "Unknown"  # Default to "Unknown" if name is None
    }
    users_collection.insert_one(user_dict)
    
    user_data = {"sub": user.email, "name": user.name if user.name else "Unknown"}
    access_token = create_access_token(user_data)
    refresh_token = create_refresh_token(user_data)
    
    response.set_cookie(
        "accessToken", access_token, httponly=True, secure=False, samesite="strict",
        max_age=15 * 60
    )
    response.set_cookie(
        "refreshToken", refresh_token, httponly=True, secure=False, samesite="strict",
        max_age=7 * 24 * 60 * 60
    )
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
async def login(user: User, response: Response):
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Retrieve only name from database
    user_data = {
        "sub": db_user["email"],
        "name": db_user.get("name", "Unknown")
    }
    access_token = create_access_token(user_data)
    refresh_token = create_refresh_token(user_data)
    
    response.set_cookie(
        "accessToken", access_token, httponly=True, secure=False, samesite="strict",
        max_age=15 * 60
    )
    response.set_cookie(
        "refreshToken", refresh_token, httponly=True, secure=False, samesite="strict",
        max_age=7 * 24 * 60 * 60
    )
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/refresh")
async def refresh_token(refresh_token: str, response: Response):
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    email = payload.get("sub")
    name = payload.get("name", "Unknown")
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Retrieve only name from database
    user_data = {
        "sub": db_user["email"],
        "name": db_user.get("name", "Unknown")
    }
    access_token = create_access_token(user_data)
    new_refresh_token = create_refresh_token(user_data)
    
    response.set_cookie(
        "accessToken", access_token, httponly=True, secure=False, samesite="strict",
        max_age=15 * 60
    )
    response.set_cookie(
        "refreshToken", new_refresh_token, httponly=True, secure=False, samesite="strict",
        max_age=7 * 24 * 60 * 60
    )
    
    return {
        "message": "Token refreshed",
        "accessToken": access_token,
        "refreshToken": new_refresh_token,
        "user": {
            "id": str(db_user["_id"]),
            "name": user_data["name"]
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
        "name": user.get("name", "Unknown")
    }