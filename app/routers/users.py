# app/routers/users.py

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import EmailStr
from app.redis import redis_client
from app.utils import send_email
from app.auth import get_current_user
from app import auth, models, schemas, database, config
from app.auth import get_current_user
from app.database import get_db
from app.schemas import PasswordChangeRequest

from .. import database, models, schemas, auth

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.get("/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(auth.get_current_user)):
    """ Obtiene el perfil del usuario autenticado. """
    return current_user

@router.get("/", response_model=List[schemas.UserOut])
def get_users(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    """
    Obtiene una lista de todos los usuarios.
    Requiere autenticación. Idealmente, debería restringirse a administradores.
    """
    users = db.query(models.User).all()
    return users


@router.post("/change-password")
def change_password(
    payload: schemas.PasswordChangeRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """ Cambia la contraseña del usuario autenticado. """
    if not auth.verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if payload.new_password != payload.confirm_new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match")

    current_user.hashed_password = auth.get_password_hash(payload.new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@router.post("/deactivate-me")
def deactivate_current_user(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """ Desactiva la cuenta del usuario autenticado. """
    current_user.is_active = False
    db.commit()
    return {"message": "Your account has been deactivated."}