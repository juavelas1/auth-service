from fastapi.responses import JSONResponse
from fastapi import status
import random
import string
import smtplib
from email.mime.text import MIMEText
import os
import requests


# === Respuesta estandarizada de éxito ===
def success_response(message: str, data: dict = None, code: int = status.HTTP_200_OK):
    response = {"success": True, "message": message}
    if data is not None:
        response["data"] = data
    return JSONResponse(content=response, status_code=code)


# === Respuesta de error personalizada ===
def error_response(message: str, code: int = status.HTTP_400_BAD_REQUEST):
    return JSONResponse(
        content={"success": False, "error": message},
        status_code=code
    )


# === Validación simple de contraseñas fuertes ===
def is_strong_password(password: str) -> bool:
    """
    Basic strong password validation:
    - At least 8 characters
    - Includes a number
    - Includes a capital letter
    """
    import re
    return (
        len(password) >= 8 and
        re.search(r"\d", password) and
        re.search(r"[A-Z]", password)
    )



def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def generate_token(length=40):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN")
MAILGUN_FROM = os.getenv("MAILGUN_FROM")

def send_email(to_email: str, subject: str, text: str):
    if not all([MAILGUN_API_KEY, MAILGUN_DOMAIN, MAILGUN_FROM]):
        raise ValueError("Mailgun configuration is missing in environment variables.")

    return requests.post(
        " https://api.mailgun.net/v3/mailgun.windconsul.com/messages",
        auth=("api", os.getenv(MAILGUN_API_KEY, MAILGUN_API_KEY)),
        data={
            "from": MAILGUN_FROM,
            "to": [to_email],
            "subject": subject,
            "text": text
        }
    )