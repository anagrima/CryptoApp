
"""
MODULO PARA ALMACENAMIENTO DE TICKETS CON CIFRADO HIBRIDO
"""


import json
from pathlib import Path
from .models import Ticket
from ..config import DATA_PATH
from ..logger import logger
from ..crypto.hybrid import encrypt_hybrid_bundle, decrypt_hybrid_bundle
from ..crypto.asymmetric import deserialize_public_key, deserialize_private_key
from ..auth.auth_service import get_user_public_key
from ..sign.sign_service import verify_transfer_authorization

# cache de claves privadas cargadas en memoria para evitar pedir la contraseña repetidamente
_PRIVATE_KEY_CACHE: dict[str, object] = {}

# base de datos simulada de tickets en la carpeta data
TICKETS_DB_PATH = Path(DATA_PATH) / "tickets.db"
TICKETS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# funcion para cargar la base de datos de tickets
def _load_ticket_db() -> dict:
    if not TICKETS_DB_PATH.exists():
        return {}
    try:
        return json.loads(TICKETS_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {} # si esta corrupto, se devuelve vacio

# funcion para guardar la base de datos de tickets
def _save_ticket_db(db: dict):
    TICKETS_DB_PATH.write_text(json.dumps(db, indent=2), encoding="utf-8")


# funcion para obtener la clave publica deserializada de un cliente
def _get_client_public_key_obj(username: str):
    pem = get_user_public_key(username)
    if not pem:
        logger.debug(f"No se encontró clave pública para {username}")
        raise ValueError(f"No se encontró clave pública para {username}")
    return deserialize_public_key(pem)

# funcion para obtener la clave privada deserializada de un cliente
# esta funcion la usa el cliente para descifrar sus tickets
def _get_client_private_key_obj(username: str):
    """Obtiene el OBJETO de clave privada del cliente desde su archivo local."""
    key_file = Path("client/mock_client_keys") / f"{username}_keys.json"
    if not key_file.exists():
        logger.debug(f"No se encontró el archivo de claves para {username}")
        raise FileNotFoundError("Archivo de claves del cliente no encontrado.")
    
    try:
        # devolver de la cache si ya la tenemos
        if username in _PRIVATE_KEY_CACHE:
            return _PRIVATE_KEY_CACHE[username]
        data = json.loads(key_file.read_text(encoding="utf-8"))
        pem = data["private_key_pem"]
        # si el JSON incluye la contraseña, intentar usarla primero
        pwd_field = data.get("private_key_password")
        if pwd_field:
            try:
                priv = deserialize_private_key(pem, password=pwd_field.encode('utf-8'))
                _PRIVATE_KEY_CACHE[username] = priv
                return priv
            except Exception as e_pwd:
                logger.debug(f"Fallo al cargar la clave privada de {username} usando 'private_key_password' del JSON: {e_pwd}")

        # intentar deserializar sin contraseña
        try:
            priv = deserialize_private_key(pem, password=None)
            _PRIVATE_KEY_CACHE[username] = priv
            return priv
        except Exception:
            # si falla o no hay password en JSON, intentar pedir la contraseña al usuario vía GUI
            try:
                import tkinter.simpledialog as sd
                pwd = sd.askstring("Contraseña clave privada", f"Introduce la contraseña de la clave privada de {username}:", show='*')
                if pwd is None:
                    raise ValueError("Contraseña no proporcionada por el usuario")

                # deserializar la clave privada para devolverla como objeto
                priv = deserialize_private_key(pem, password=pwd.encode('utf-8'))
                _PRIVATE_KEY_CACHE[username] = priv
                return priv
            except Exception as e2:
                logger.debug(f"Fallo al cargar la clave privada de {username}: {e2}")
                raise
    except Exception as e:
        logger.debug(f"Fallo al cargar la clave privada de {username}: {e}")
        raise


def clear_private_key_cache(username: str | None = None):
    """Limpia la cache de claves privadas. Si 'username' es None limpia toda la cache."""
    if username is None:
        _PRIVATE_KEY_CACHE.clear()
    else:
        _PRIVATE_KEY_CACHE.pop(username, None)

# FUNCIONES DE MANEJO DE TICKETS EN LA DB

# funcion para añadir un ticket cifrado a la base de datos
def add_ticket(ticket: Ticket):
    # cifra el ticket USANDO LA CLAVE PUBLICA DEL CLIENTE y lo guarda
    logger.info(f"STORE: Recibido 'add_ticket' para {ticket.username}")
    try:
        # busca la clave publica del cliente
        client_public_key = _get_client_public_key_obj(ticket.username)
        
        # serializar el ticket a bytes para almacenar
        ticket_bytes = ticket.to_json_bytes()

        # AAD para mayor seguridad: vincula el cifrado al usuario y ticket_id
        aad_ = f"{ticket.username}|{ticket.ticket_id}".encode("utf-8")
        
        # cifrar usando el sistema de cifrado hibrido, esto crea un paquete cifrado que SOLO el cliente puede abrir
        encrypted_bundle_bytes = encrypt_hybrid_bundle(
            public_key=client_public_key,
            data=ticket_bytes,
            aad=aad_
        )
        
        # guardar en la db de tickets
        db = _load_ticket_db()
        if ticket.username not in db:
            db[ticket.username] = {}
        
        # guardar el bundle como string (es formato JSON)
        db[ticket.username][ticket.ticket_id] = encrypted_bundle_bytes.decode('utf-8')
        _save_ticket_db(db)
        
        logger.info(f"STORE: Ticket {ticket.ticket_id} guardado y cifrado.")

    except Exception as e:
        logger.debug(f"STORE: Fallo al añadir ticket: {e}")
        raise


# funcion que llama el cleinte para obtener y descifrar un ticket suyo
def get_ticket_decrypted(username: str, ticket_id: str) -> Ticket | None:
    logger.info(f"STORE: Recibido 'get_ticket_decrypted' para {ticket_id}")
    try:
        db = _load_ticket_db()
        encrypted_bundle_str = db.get(username, {}).get(ticket_id)
        
        if not encrypted_bundle_str:
            logger.warning(f"STORE: Ticket no encontrado: {ticket_id}")
            return None
            
        # paquete se pasa de str (como se almacena) a bytes para poder descifrar  
        encrypted_bundle_bytes = encrypted_bundle_str.encode('utf-8')

        # para que el cliente recupere s clave privada
        client_private_key = _get_client_private_key_obj(username)
        
        # descifrar el paquete
        decrypted_ticket_bytes = decrypt_hybrid_bundle(
            private_key=client_private_key,
            cipher_data=encrypted_bundle_bytes
        )
        
        # deserializar de JSON a objeto Ticket
        ticket = Ticket.from_json_bytes(decrypted_ticket_bytes)
        
        logger.info(f"STORE: Ticket {ticket_id} descifrado y devuelto.")
        return ticket

    except Exception as e:
        logger.debug(f"STORE: Fallo al descifrar ticket {ticket_id}: {e}")
        return None


# funcion que retorna los tickets que tiene un usuario
def list_user_tickets(username: str) -> list[str]:
    db = _load_ticket_db()
    return list(db.get(username, {}).keys())
