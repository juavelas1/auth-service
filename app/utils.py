from fastapi.responses import JSONResponse
from fastapi import status


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
