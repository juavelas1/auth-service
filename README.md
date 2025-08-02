# WindCRM – Auth Service

This is the **authentication and token management microservice** for the [WindCRM](https://github.com/your-org/WindCRM) system.  
It provides secure login, registration, token-based session management, and token revocation via Redis.

---

## 🚀 Tech Stack

- **FastAPI** – modern Python web framework
- **PostgreSQL** – user data persistence
- **Redis** – JWT blacklist management
- **Docker** – containerized service
- **Pydantic v2** – data validation
- **Uvicorn** – ASGI server for production
- **OAuth2 + JWT** – authentication scheme

---

## 📦 Features

- User registration (`POST /register`)
- Secure login with password hashing (`POST /login`)
- Token generation using JWT
- Token blacklist via Redis (`POST /logout`)
- Protected endpoint to get current user (`GET /me`)
- Swagger UI documentation

---

## 📄 Environment Variables (`.env`)

Create a `.env` file in the root of the service:

```env
# Database
POSTGRES_DB=authdb
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
DATABASE_URL=postgresql://postgres:postgres@auth-db:5432/authdb

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# JWT
SECRET_KEY=your-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256

# Misc
ENV=development
