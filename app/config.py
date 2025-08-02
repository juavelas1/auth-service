import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from project root when running locally
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

# === General settings ===
ENV = os.getenv("ENV", "development")

# === JWT settings ===
SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# === Database ===
DATABASE_URL = os.getenv("DATABASE_URL")

# === Redis settings for token blacklisting ===
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
