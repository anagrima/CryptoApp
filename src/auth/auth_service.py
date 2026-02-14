# funciones de alto nivel para registro y autenticacion de usuarios
from .user_store import get_user_public_key_pem, register_user, verify_credentials
from .password_policy import valid_password
from ..logger import logger
from ..common.validators import ensure_valid_phone_number

""" ESTA ES LA CLASE CON LA QUE SE INTERACTUA DESDE FUERA DEL MODULO AUTH PARA REGISTRO E INICIO DE SESION DE USUARIOS,
Y DELEGA TAREAS A USER_STORE Y PASSWORD_POLICY CUANDO PROCEDE """

# funcion que registra un usuario si la conrtraseña cumple la politica de seguridad
def register(username: str, password: str, phone: str, public_key_pem: str) -> bool:
    # si falta algun dato obligatorio o es solo espacios --> devuelve False
    for field in (username, password, phone, public_key_pem):
        if field is None or (isinstance(field, str) and field.strip() == ""):
            return False
    # si la contraseña no cumple --> se loguea el fallo y se devuelve False
    if not valid_password(password):
        logger.debug("Registro fallido: la contraseña no cumple con la política.")
        return False
    
    if ensure_valid_phone_number(phone):
        logger.debug("Registro fallido: el número de teléfono no es válido")
        return False
    
    # si la contraseña es valida --> delega el registro al user_store
    return register_user(username, password, phone, public_key_pem)

# funcion que verifica las credenciales de usuario para iniciar sesion
def login(username: str, password: str) -> bool:
    # devuelve True si las credenciales son correctas --> False en caso contrario
    return verify_credentials(username, password)

# devuelve la clave publica de un cliente con username
# esta funcion se usa para no acceder directamente al user_store desde fuera de auth
def get_user_public_key(username: str):
    return get_user_public_key_pem(username)