from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from jose import jwt

from . import auth, models, schemas, database, config
from app.auth import get_current_user

router = APIRouter()


# === Registro de usuario ===
@router.post("/register", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.SessionLocal)):
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
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.SessionLocal)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

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
