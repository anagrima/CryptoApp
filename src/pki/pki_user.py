from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from ..crypto.asymmetric import deserialize_private_key, deserialize_public_key
from ..auth.user_store import get_user_private_key_pem, get_user_public_key_pem
from ..logger import logger
from ..config import KEYSTORE_PATH
from pathlib import Path
# from cryptography.x509 import PolicyBuilder

# basandose en la plantilla de la documentacion oficial de cryptography.io
# https://cryptography.io/en/latest/x509/tutorial/


# funcion para crear una CSR para un usuario dado su nombre de usuario
def create_user_csr(username: str, private_key) -> bytes:

    # saca las claves del fichero de claves de usuario, que se crearon al registrarlo
    public_key_pem = get_user_public_key_pem(username)
    if public_key_pem is None or private_key is None:
        logger.debug(f"Claves no encontradas para el usuario {username}")
        return None

    # deserializa porque se guardan serializadas en formato PEM
    public_key = deserialize_public_key(public_key_pem)

    # creacion de una solicitud de firma de certificado (CSR)
    # algunos campos los rellenara la AC al firmar el certificado (como el issuer, numero de serie)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # campos del certificado
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SeguriTicket"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Usuario: {username}"),
    ])).sign(private_key, hashes.SHA256())


    # guardar el CSR en un archivo PEM
    csr_path = Path(KEYSTORE_PATH) / f"csr_{username}.pem"
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        logger.debug(f"No se pudo guardar el CSR para {username}: {e}")
    return csr.public_bytes(serialization.Encoding.PEM)
