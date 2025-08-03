from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from . import config


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

# === Schema for Forgot Password request ===
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

# === Schema for email verification ===
class VerifyCodeRequest(BaseModel):
    email: EmailStr
    code: str

# === Schema for password reset request ===
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str

# === Schema for email requests ===
class EmailRequest(BaseModel):
    email: EmailStr

# === Schema for user activation ===
class ActivateUserRequest(BaseModel):
    email: EmailStr
    code: str

# NUEVO ESQUEMA PARA LA RESPUESTA DE AUDITORÍA
class AuditLog(BaseModel):
    id: int
    user_id: int | None = None # Puede ser nulo
    action: str
    endpoint: str
    method: str
    ip_address: str
    timestamp: datetime

    class Config:
        from_attributes = True # En Pydantic v2, antes orm_mode = True
        orm_mode = True  # Permite que Pydantic use los modelos de SQLAlchemy directamente

# === Schema for password reset request ===
class PasswordResetRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str
    confirm_password: str