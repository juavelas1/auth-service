from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from . import config

# Crear el motor de conexión a PostgreSQL
engine = create_engine(config.DATABASE_URL)

# Crear sesión para uso en dependencias
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base para modelos
Base = declarative_base()
