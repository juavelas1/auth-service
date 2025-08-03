from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from jose import jwt
from typing import List
from app.database import get_db
from app.utils import generate_code, generate_token, send_email
from pydantic import EmailStr
from . import auth, models, schemas, database, config
from app.auth import get_current_user
import secrets
from app.redis import redis_client

router = APIRouter()


# === Registro de usuario ===
@router.post("/register", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    existing = auth.get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

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


# === Login (retorna token) ===
@router.post("/login", response_model=schemas.Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is deactivated")

    token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


# === Logout (blacklist de token actual) ===
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
        raise HTTPException(status_code=400, detail="Invalid token")
    return {"message": "Successfully logged out"}


# === Obtener usuario actual ===
@router.get("/me", response_model=schemas.UserOut)
def get_me(current_user=Depends(get_current_user)):
    return current_user


@router.get("/users", response_model=List[schemas.UserOut])
def get_users(db: Session = Depends(database.get_db)):
    users = db.query(models.User).all()
    return users

@router.post("/change-password")
def change_password(
    payload: schemas.PasswordChangeRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    if not auth.verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if payload.new_password != payload.confirm_new_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")

    hashed = auth.get_password_hash(payload.new_password)
    current_user.hashed_password = hashed
    db.commit()

    return {"message": "Password updated successfully"}

@router.post("/forgot-password")
def forgot_password(email: EmailStr, db: Session = Depends(get_db)):
    user = auth.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    code = secrets.token_urlsafe(4)  # Código corto y seguro
    redis_client.setex(f"reset_code:{email}", 600, code)  # 10 min

    send_email(
        to_email=email,
        subject="Password Reset Code",
        text=f"Your reset code is: {code}"
    )
    print(f"Reset code for {email}: {code}")  # Debugging line, remove in production
    return {"message": "Reset code sent to your email"}

@router.post("/verify-reset-code")
def verify_reset_code(email: EmailStr, code: str):
    stored = redis_client.get(f"reset_code:{email}")
    if stored is None or stored != code:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    return {"message": "Code verified. You can now reset your password"}


@router.post("/reset-password")
def reset_password(
    email: EmailStr,
    code: str,
    new_password: str,
    confirm_password: str,
    db: Session = Depends(get_db)
):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    stored = redis_client.get(f"reset_code:{email}")
    if stored is None or stored != code:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    user = auth.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = auth.get_password_hash(new_password)
    db.commit()

    send_email(
        to_email=email,
        subject="Password Changed",
        text="Your password has been successfully updated."
    )

    redis_client.delete(f"reset_code:{email}")
    return {"message": "Password changed successfully"}

@router.post("/deactivate-user")
def deactivate_user(req: schemas.EmailRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    db.commit()
    return {"message": "User has been deactivated. Logging out..."}


@router.post("/request-reactivation")
def request_reactivation(req: schemas.EmailRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User is already active")

    code = generate_code()
    redis_client.setex(f"reactivate_code:{req.email}", 600, code)

    send_email(
        req.email,
        "Código de reactivación",
        f"Tu código de reactivación es: {code}"
    )

    return {"message": "Verification code sent to email"}


@router.post("/activate-user")
def activate_user(req: schemas.ActivateUserRequest, db: Session = Depends(get_db)):
    stored = redis_client.get(f"reactivate_code:{req.email}")
    if stored is None or stored != req.code:
        raise HTTPException(status_code=400, detail="Invalid or expired activation code")

    user = db.query(models.User).filter_by(email=req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = True
    db.commit()

    return {"message": "User has been successfully reactivated"}
