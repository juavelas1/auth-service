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
class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True  # Pydantic v2

class Config:
    from_attributes = True


# === Schema for token response ===
class Token(BaseModel):
    access_token: str
    token_type: str

# === Schema for password change request ===
class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str
