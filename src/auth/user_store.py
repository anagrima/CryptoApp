# funciones para gestion de usuarios: registro, almacenamiento y verificacion de credenciales
import bcrypt
import json
from pathlib import Path
from ..logger import logger
from ..config import DATA_PATH

# base de datos simple en JSON para almacenar usuarios y hashes de contraseñas
DB_PATH = Path(DATA_PATH) / "users.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# funcion para cargar la base de datos de usuarios
def _load_db() -> dict:
    # lectura segura: si el archivo no es un json valido --> se respalda y se devuelve {}
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"user_store: DB corrupta ({e}). Se creará una nueva base.")
        # copia de respaldo: users.db.corrupt + timestamp
        backup = DB_PATH.with_suffix(".corrupt")
        try:
            DB_PATH.rename(backup)
            logger.info(f"Se ha renombrado el archivo corrupto a {backup.name}")
        except Exception as e2:
            logger.debug(f"No se pudo respaldar la base corrupta: {e2}")
        return {}

# funcion para guardar la base de datos de diccionarios de usuarios
def _save_db(db: dict) -> None:
    # guarda el diccionario en el archivo JSON de forma legible
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

# registra un nuevo usuario con contraseña cifrada
def register_user(username: str, password: str, phone: str, public_key_pem: str) -> bool:
    # carga la base, comprueba existencia y guarda el hash si es nuevo
    db = _load_db()
    # si el usuario ya existe --> no registra y devuelve False
    if username in db:
        logger.debug("Registro fallido: usuario ya existe.")
        return False
    salt = bcrypt.gensalt()
    # bcrypt solo admite hasta 72 bytes, truncamos si es necesario
    hashed = bcrypt.hashpw(password.encode()[:72], salt).decode()
    db[username] = {"password_hash": hashed, "phone_number": phone, "public_key_pem": public_key_pem}
    _save_db(db)
    logger.info(f"Usuario registrado: {username} con clave pública {public_key_pem[:30]}")
    return True

# funcion que verifica las credenciales de un usuario
def verify_credentials(username: str, password: str) -> bool:
    # carga la base y valida el password comparando con el hash almacenado
    if password is None:
        logger.debug("Inicio de sesión fallido: contraseña None.")
        return False
    db = _load_db()
    # si el usuario no existe ---> devuelve False
    if username not in db:
        logger.debug("Inicio de sesión fallido: usuario no encontrado.")
        return False
    stored = db[username]["password_hash"].encode()
    # bcrypt solo admite hasta 72 bytes, truncamos si es necesario
    ok = bcrypt.checkpw(password.encode()[:72], stored)
    # log con resultado del intento (exito/fallido)
    logger.info(f"Intento de inicio de sesión para {username}: {'éxito' if ok else 'fallido'}")
    return ok


def get_user_phone(username: str) -> str | None:
    # Devuelve el número de telefono (sin prefijo) de un usuario, o None si no se encuentra
    db = _load_db()
    user_data = db.get(username, {})
    return user_data.get("phone_number")

# devuelve la clave publica de un cliente con username
def get_user_public_key_pem(username: str) -> str | None:
    db = _load_db()
    user_data = db.get(username, {})
    return user_data.get("public_key_pem")

# devuelve la clave privada
def get_user_private_key_pem(username: str) -> str | None:
    db = _load_db()
    return None  # las claves privadas no se almacenan en este sistema