import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from ..crypto.asymmetric import generate_key_pair
from cryptography.hazmat.primitives import serialization
from ..pki.pki_store import save_private_key, save_certificate, load_certificate
from ..config import KEYSTORE_PATH
from ..logger import logger


# funcion para crear un certificado para la Autoridad Certificadora Raiz
def create_root_ca_certificate():

    # generar par de claves para la CA raiz
    private_key, public_key = generate_key_pair()


    # guardar la clave privada y luego el certificado en el keystore
    try:
        save_private_key("root_ca", private_key)
    except Exception as e:
        logger.error(f"No se pudo guardar la clave privada de la CA raíz: {e}")
        raise



    # TODO: mantener registro de números de serie en una DB si se requiere

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SeguriTicket"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Autoridad Certificadora Raíz"),
    ])

    cert_root = x509.CertificateBuilder().subject_name(
        subject

    # coinciden subject e issuer porque es un certificado autofirmado
    ).issuer_name(
        subject

    # clave publica de la CA raiz
    ).public_key(
        public_key

    # numero de serie unico al azar
    ).serial_number(
        x509.random_serial_number()

    # fechas de validez
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # 10 anyos de validez para el certificado
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    
    # extensiones
    ).add_extension(
        # extension para identificar que el certificado es de una CA
        x509.BasicConstraints(ca=True, path_length=None),
        # la extension para indicar ca=True es critica, por lo que si no la entiende el validador
        # o hay algun problema, debe rechazar el certificado y no proseguir
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,

    # firmado con la clave privada de la CA raiz
    ).sign(private_key, hashes.SHA256())

    # guardar en almacenamiento el certificado de la CA raiz
    try:
        save_certificate("root_ca", cert_root)
    except Exception as e:
        logger.error(f"No se pudo guardar el certificado raíz: {e}")

    logger.info(f"CA raíz creada en {KEYSTORE_PATH}")
    return private_key, cert_root