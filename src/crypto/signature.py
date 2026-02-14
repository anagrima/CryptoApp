# generar firmas digitales usando RSA-PSS-SHA256

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from ..logger import logger
from ..common.constants import ALGO_RSA_PSS_SHA256

# genera una firma digital para los datos usando la clave privada y RSA-PSS-SHA256
def sign_data(private_key, data: bytes) -> bytes:
    # generar la firma digital
    try:
        signature = private_key.sign(
            data,
            # usar PSS con MGF1 y SHA256
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), # usar MGF1 con SHA256
                salt_length=padding.PSS.MAX_LENGTH # usar la longitud máxima de sal
            ),
            hashes.SHA256() # usar SHA256 como funcion hash
        )
        key_size = private_key.key_size # obtener el tamaño de la clave en bits
        logger.info(f"Firma generada con éxito usando {ALGO_RSA_PSS_SHA256} y clave de {key_size} bits.")
        return signature
    # capturar errores durante la firma
    except Exception as e:
        logger.error(f"Error al generar la firma: {e}")
        raise

# verifica una firma digital usando la clave publica y RSA-PSS-SHA256
def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    # verificar la firma digital
    try:
        public_key.verify(
            signature,
            data,
            # usar PSS con MGF1 y SHA256
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), # usar MGF1 con SHA256
                salt_length=padding.PSS.MAX_LENGTH # usar la longitud máxima de sal
            ),
            hashes.SHA256() # usar SHA256 como funcion hash
        )
        logger.info(f"Firma verificada con éxito usando {ALGO_RSA_PSS_SHA256}.")
        return True
    except InvalidSignature:
        # firma no valida (caso esperado cuando la verificacion falla)
        logger.info(f"Firma inválida: verificación falló con {ALGO_RSA_PSS_SHA256}.")
        return False
    except Exception as e:
        # errores inesperados (I/O, deserializacion, fallos internos)
        logger.error(f"Error inesperado al verificar la firma: {e}")
        raise