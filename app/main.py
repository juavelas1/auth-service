from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models, database
from .middleware import audit_log_middleware
# --- CAMBIO: Se importan los nuevos módulos de rutas ---
from .routers import auth, users, audit

# Crear tablas si no existen
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="WindCRM Auth Service",
    version="1.0.0",
    description="Microservice for user authentication and token management",
    root_path="/auth" # Cambiado para que coincida con la ruta del servicio
)

# --- Se mantienen los middlewares como estaban ---
# Añadir middleware de auditoría
app.middleware("http")(audit_log_middleware)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambiar en producción a dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CAMBIO: Se incluye cada router por separado ---
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(audit.router)

@app.get("/", tags=["Root"])
def read_root():
    return {"message": "Welcome to the WindCRM Auth Service"}