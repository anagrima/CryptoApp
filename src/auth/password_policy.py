# funcion para validar que una contraseña cumple la politica de seguridad definida
from ..config import PASSWORD_MIN_LENGTH
from ..common.validators import ensure_password_policy

# funcion que verifica si la contraseña cumple los requisitos minimos de seguridad
def valid_password(password: str) -> bool:
    return ensure_password_policy(password, PASSWORD_MIN_LENGTH)
