# app/routers/auth.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from jose import jwt
from pydantic import EmailStr
import secrets
from app.auth import get_current_user
from app.redis import redis_client
from app.utils import send_email
from app.schemas import PasswordResetRequest, EmailRequest, ActivateUserRequest
from app import utils

from .. import database, models, schemas, config, auth, utils
from ..redis import redis_client

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post("/register", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    existing = auth.get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/login", response_model=schemas.Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is deactivated")

    token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/logout")
def logout(token: str = Depends(auth.oauth2_scheme)):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        exp = payload.get("exp")
        now = datetime.utcnow().timestamp()
        ttl = int(exp - now)
        if ttl > 0:
            auth.blacklist_token(token, ttl)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    return {"message": "Successfully logged out"}

@router.post("/forgot-password")
def forgot_password(email: EmailStr, db: Session = Depends(database.get_db)):
    user = auth.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    code = secrets.token_urlsafe(4)
    redis_client.setex(f"reset_code:{email}", 600, code)
    utils.send_email(to_email=email, subject="Password Reset Code", text=f"Your reset code is: {code}")
    return {"message": "Reset code sent to your email"}

@router.post("/reset-password")
def reset_password(req: schemas.PasswordResetRequest, db: Session = Depends(database.get_db)):
    if req.new_password != req.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    stored_code = redis_client.get(f"reset_code:{req.email}")
    if stored_code is None or stored_code != req.code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code")

    user = auth.get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = auth.get_password_hash(req.new_password)
    db.commit()
    utils.send_email(to_email=req.email, subject="Password Changed", text="Your password has been successfully updated.")
    redis_client.delete(f"reset_code:{req.email}")
    return {"message": "Password changed successfully"}

@router.post("/verify-reset-code")
def verify_reset_code(email: EmailStr, code: str):
    stored = redis_client.get(f"reset_code:{email}")
    if stored is None or stored != code:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    return {"message": "Code verified. You can now reset your password"}


@router.post("/request-reactivation")
def request_reactivation(req: schemas.EmailRequest, db: Session = Depends(database.get_db)):
    user = auth.get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already active")

    code = utils.generate_code()
    redis_client.setex(f"reactivate_code:{req.email}", 600, code)
    utils.send_email(req.email, "Reactivation Code", f"Your reactivation code is: {code}")
    return {"message": "Verification code sent to email"}

@router.post("/activate-user")
def activate_user(req: schemas.ActivateUserRequest, db: Session = Depends(database.get_db)):
    stored = redis_client.get(f"reactivate_code:{req.email}")
    if stored is None or stored != req.code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation code")

    user = auth.get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = True
    db.commit()
    return {"message": "User has been successfully reactivated"}