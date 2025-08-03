from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PasswordReset(Base):
    __tablename__ = "password_resets"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    code = Column(String, nullable=False)
    token = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime)
    is_verified = Column(Boolean, default=False)

# NUEVO MODELO PARA LA AUDITORÍA
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Puede ser nulo para acciones no autenticadas (ej. login)
    action = Column(String, index=True) # Ej: "user_login", "get_profile"
    endpoint = Column(String) # Ej: "/login"
    method = Column(String) # Ej: "POST"
    ip_address = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")