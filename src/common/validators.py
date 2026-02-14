# funciones de validacion para parametros de seguridad y contraseñas
from ..config import AES_KEY_MIN_BITS, HMAC_KEY_MIN_BITS, RSA_MIN_BITS, TLF_LENGTH

# funcion para verificar que la longitud de bits cumple el minimo requerido
def ensure_min_bits(bits: int, min_bits: int, name: str):
    if bits < min_bits:
        raise ValueError(f"{name}: longitud mínima {min_bits} bits.")

# funcion para verificar que el IV para AES-GCM es de 12 bytes (96 bits)
def ensure_gcm_iv(iv: bytes):
    if len(iv) != 12:
        raise ValueError("AES-GCM: IV debe ser de 12 bytes (96 bits).")

#  funcion para verificar que la contraseña cumple la politica minima
def ensure_password_policy(password: str, min_length: int = 12) -> bool:
    # longitud minima
    if len(password) < min_length:
        return False
    # comprueba mayusculas, minusculas, digitos y simbolos
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol

def ensure_valid_phone_number(phone) -> bool:
    if not phone.isdigit() or len(phone) != TLF_LENGTH:
        return False