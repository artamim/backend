from pydantic import BaseModel, EmailStr

class User(BaseModel):
    email: EmailStr
    password: str
    name: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str