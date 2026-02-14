# funciones para generacion de claves y computar/verificar HMAC-SHA256
from os import urandom
from cryptography.hazmat.primitives import hashes, hmac
from ..logger import logger
from ..config import HMAC_KEY_MIN_BITS
from ..common.constants import ALGO_HMAC_SHA256
from ..common.validators import ensure_min_bits

# funcion para generar una clave segura para HMAC de la longitud especificada
def generate_hmac_key(bits: int = 256) -> bytes:
    # valida que la longitud cumpla el minimo definido en la configuracion
    ensure_min_bits(bits, HMAC_KEY_MIN_BITS, "HMAC key")
    return urandom(bits // 8)

# funcion para calcular el valor HMAC-SHA256 para un mensaje dado y una clave
def compute_hmac(key: bytes, message: bytes) -> bytes:
    # se crea el objeto hmac y se actualiza con el mensaje
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    tag = h.finalize()
    # loguea algoritmo y tamano de clave en bits
    logger.info(f"HMAC compute: algorithm={ALGO_HMAC_SHA256}, key_bits={len(key)*8}")
    return tag

# funcion para verificar si el HMAC proporcionado es valido para el mensaje y la clave
def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    # reconstruye el hmac y verifica --> devuelve True si es valido
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(tag)
        logger.info(f"HMAC verify: valid algorithm={ALGO_HMAC_SHA256}")
        return True
    except Exception:
        logger.info(f"HMAC verify: invalid algorithm={ALGO_HMAC_SHA256}")
        return False
