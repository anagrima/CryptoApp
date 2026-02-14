# configuracion global para la aplicacion
import os
import os, binascii
from pathlib import Path

# rutas y parametros del archivo de log
LOG_FILE = os.getenv("LOG_FILE", "crypto_app.log")

# parametros de seguridad
AES_KEY_MIN_BITS = 128  # AES-128
HMAC_KEY_MIN_BITS = 128 # HMAC-SHA256
RSA_MIN_BITS = 2048     # RSA-2048

PASSWORD_MIN_LENGTH = 12 # longitud minima de contraseñas

# rutas para almacenar datos y llaves
DATA_PATH = os.getenv("DATA_PATH", "data")
KEYSTORE_PATH = os.getenv("KEYSTORE_PATH", os.path.join(DATA_PATH, "keystore"))

# tickets
DATA_PATH = os.getenv("DATA_PATH", "data")
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
AES_TICKETS_KEY_HEX = os.getenv("AES_TICKETS_KEY_HEX", "")
# SMS_2FA_ENABLED = os.getenv("SMS_2FA_ENABLED", "false").lower() == "true"
SMS_2FA_ENABLED = True

# telefono para SMS
TLF_LENGTH = 9 # (longitud de numeros de telefono en Espanya sin prefijo de pais)

def load_or_create_tickets_key() -> bytes:
    keyfile = Path(DATA_PATH) / "aes_tickets.key"
    if AES_TICKETS_KEY_HEX:
        return binascii.unhexlify(AES_TICKETS_KEY_HEX.strip())
    if keyfile.exists():
        return binascii.unhexlify(keyfile.read_text().strip())
    from .crypto.symmetric import generate_aes_key
    k = generate_aes_key(256)
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(binascii.hexlify(k).decode("ascii"))
    return k