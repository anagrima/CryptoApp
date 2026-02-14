# funciones para generacion de claves y cifarado/descifrado simetrico usando AES-GCM
from os import urandom
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..logger import logger
from ..config import AES_KEY_MIN_BITS
from ..common.constants import ALGO_AES_GCM
from ..common.validators import ensure_min_bits, ensure_gcm_iv

# funcion para generar una clase AES segura de la longitud especificada
def generate_aes_key(bits: int = 256) -> bytes:
    # valida la longitud minima definida en la configuracion
    ensure_min_bits(bits, AES_KEY_MIN_BITS, "AES key")
    return urandom(bits // 8)

# funcion para cifrar usando AES-GCM, retorna IV, ciphertext y AAD
def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    aesgcm = AESGCM(key)
    # iv de 12 bytes recomendado para gcm
    iv = urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, aad)
    logger.info(f"{ALGO_AES_GCM}: encrypt: algorithm={ALGO_AES_GCM}, key_bits={len(key)*8}")
    return {"iv": iv, "ciphertext": ct, "aad": aad}

# funcion para descifrar usando AES-GCM, valodando autenticidad
def decrypt_aes_gcm(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    # valida que el iv tenga 12 bytes
    ensure_gcm_iv(iv)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(iv, ciphertext, aad)
        logger.info(f"{ALGO_AES_GCM}: decrypt: algorithm={ALGO_AES_GCM}, key_bits={len(key)*8}")
        return pt
    except Exception as e:
        logger.warning(f"{ALGO_AES_GCM} decrypt failed: {type(e).__name__}")
        raise
