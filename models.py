from pydantic import BaseModel, EmailStr
from typing import Optional

# Model for registration (name is required)
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str  # Required field

# Model for login (name is optional or excluded)
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    # Option 1: Make name optional
    # name: Optional[str] = None
    # Option 2: Exclude name entirely (recommended if name isn't needed for login)

# Token model (unchanged)
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    

class RefreshTokenRequest(BaseModel):
    refresh_token: str