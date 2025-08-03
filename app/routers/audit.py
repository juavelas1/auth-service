# app/routers/audit.py

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from .. import database, models, schemas, auth

router = APIRouter(
    prefix="/audit",
    tags=["Audit"]
)

@router.get("/{username}", response_model=List[schemas.AuditLog])
def get_user_audit_logs(
    username: str,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Obtiene todos los registros de auditoría para un usuario específico.
    Este endpoint está protegido y requiere autenticación.
    """
    user_to_audit = db.query(models.User).filter(models.User.email == username).first()
    if not user_to_audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with username '{username}' not found"
        )

    audit_logs = db.query(models.AuditLog).filter(models.AuditLog.user_id == user_to_audit.id).order_by(models.AuditLog.timestamp.desc()).all()
    return audit_logs