from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from . import config

# Crear el motor de conexión a PostgreSQL
engine = create_engine(config.DATABASE_URL)

# Crear sesión para uso en dependencias
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base para modelos
Base = declarative_base()

# Dependencia para obtener una sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
