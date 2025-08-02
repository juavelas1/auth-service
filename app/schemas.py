from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


# === Base user schema ===
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


# === Schema for user creation (input) ===
class UserCreate(UserBase):
    password: str


# === Schema for returned user (output) ===
class UserOut(UserBase):
    id: int
    is_active: Optional[bool] = True
    created_at: Optional[datetime] = None

class Config:
    from_attributes = True


# === Schema for token response ===
class Token(BaseModel):
    access_token: str
    token_type: str
