# --- INICIO: FIX DE IMPORTACIÓN ---
import sys
import os
# Añadir el path del root del proyecto (el directorio que contiene 'src' y 'client')
# Esto es necesario para que 'from src.logger' funcione
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


import json
from src.auth.auth_service import register
from src.crypto.asymmetric import generate_key_pair, serialize_private_key, serialize_public_key
from src.crypto.asymmetric import deserialize_private_key
from src.logger import logger
from pathlib import Path
from src.pki.pki_init import initialize_user_in_pki



KEYS_DIR = Path("client/mock_client_keys")

# funcion para configurar las claves del cliente
def setup_client_keys():
    private_key, public_key = generate_key_pair(2048)

    # se devuelven ambas claves
    return private_key, public_key

# funcion para registrar un cliente junto con la generacion y guardado de sus claves
def client_register(user: str, pwd: str, phone: str, key_password: bytes | None = None) -> bool:
    # generar las claves del cliente
    private_key, public_key = setup_client_keys()

    public_key_pem = serialize_public_key(public_key)

    # serializar la clave privada, cifrada si se proporciona key_password
    priv_pem = serialize_private_key(private_key, password=key_password)

    keys_data = {
        "username": user,
        "private_key_pem": priv_pem,
        "public_key_pem": public_key_pem
    }

    key_file_path = KEYS_DIR / f"{user}_keys.json"
    # guardar las claves en fichero local
    try: 
        with open(key_file_path, "w", encoding="utf-8") as f:
            json.dump(keys_data, f)
    except IOError as e:
        logger.debug(f"No se pudo guardar las claves del cliente {user}: {e}")
        return False

    # registro efectivo del cliente en el servidor. register es funcion de src.auth.auth_service
    ok = register(user, pwd, phone, public_key_pem)

    # si el registro ha ido bien, inicializar el usuario en la PKI
    if ok:
        initialize_user_in_pki(user, private_key)
        logger.info(f"Cliente {user} registrado correctamente.")
    return ok

# funcion para cargar la clave privada del cliente desde el fichero local
def load_client_key_private_key(user: str, password: bytes = None):
    key_file_path = KEYS_DIR / f"{user}_keys.json"
    if not key_file_path.exists():
        logger.warning(f"Archivo de claves no encontrado para el cliente {user}.")
        return None
    try:
        with open(key_file_path, "r", encoding="utf-8") as f:
            keys_data = json.load(f)
        private_key_pem = keys_data.get("private_key_pem")
        if not private_key_pem:
            logger.error(f"No se encontró la clave privada en el archivo para el cliente {user}.")
            return None
        private_key = deserialize_private_key(private_key_pem, password=password)
        return private_key
    except Exception as e:
        logger.error(f"Error al cargar la clave privada para el cliente {user}: {e}")
        return None