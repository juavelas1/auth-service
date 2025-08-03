# app/middleware.py

from fastapi import Request
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from . import models, schemas, config
from .database import get_db
from .auth import oauth2_scheme
from .database import SessionLocal

# Función para obtener la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def log_audit_event(request: Request):
    db: Session = next(get_db())
    user_id = None
    token = None

    # Intentar extraer el token de la cabecera de autorización
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split("Bearer ")[1]

    # Si hay un token, intentar decodificarlo para obtener el user_id
    if token:
        try:
            payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
            username: str = payload.get("sub")
            if username:
                user = db.query(models.User).filter(models.User.username == username).first()
                if user:
                    user_id = user.id
        except JWTError:
            # El token es inválido o ha expirado, lo ignoramos para el log
            pass

    # Crear el registro de auditoría
    log_entry = models.AuditLog(
        user_id=user_id,
        action=f"{request.method}_{request.url.path.replace('/', '_').strip('_')}", # Crea una acción como "POST_login"
        endpoint=str(request.url.path),
        method=request.method,
        ip_address=request.client.host
    )

    db.add(log_entry)
    db.commit()


async def audit_log_middleware(request: Request, call_next):
    # Primero, dejamos que el endpoint se ejecute para obtener la respuesta
    response = await call_next(request)

    # Después de que el endpoint haya terminado, registramos el evento
    # Excluimos endpoints que no queremos loguear, como la documentación de la API
    if not request.url.path.startswith("/docs") and not request.url.path.startswith("/openapi.json"):
        await log_audit_event(request)

    return response