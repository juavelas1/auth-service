# app/middleware.py

from fastapi import Request
from jose import JWTError, jwt
from sqlalchemy.orm import Session

# Asegúrate de que las importaciones relativas sean correctas
from . import models, config
from .database import SessionLocal, get_db

secret_key = config.SECRET_KEY
algorithm = config.ALGORITHM

async def log_audit_event(request: Request):
    db: Session = next(get_db())
    user_id = None
    token = None

    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split("Bearer ")[1]

    if token:
        try:
            payload = jwt.decode(token, secret_key, algorithms=[algorithm])
            email: str = payload.get("sub")
            if email:
                user = db.query(models.User).filter(models.User.email == email).first()
                if user:
                    user_id = user.id
        except JWTError:
            pass

    log_entry = models.AuditLog(
        user_id=user_id,
        action=f"{request.method}_{request.url.path.replace('/', '_').strip('_')}",
        endpoint=str(request.url.path),
        method=request.method,
        ip_address=request.client.host
    )
    db.add(log_entry)
    db.commit()


# ESTA ES LA FUNCIÓN QUE TU main.py ESTÁ BUSCANDO
async def audit_log_middleware(request: Request, call_next):
    # Primero, dejamos que el endpoint se ejecute para obtener la respuesta
    response = await call_next(request)

    # Después de que el endpoint haya terminado, registramos el evento
    # Excluimos endpoints que no queremos loguear, como la documentación de la API
    if not request.url.path.startswith("/docs") and not request.url.path.startswith("/openapi.json"):
        await log_audit_event(request)

    return response