from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models, database, routes

# Crear tablas si no existen
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="WindCRM Auth Service",
    version="1.0.0",
    description="Microservice for user authentication and token management",
    root_path="/auth"
)

# CORS settings (puedes ajustarlo para producción)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambiar en producción a dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas principales
app.include_router(routes.router)
