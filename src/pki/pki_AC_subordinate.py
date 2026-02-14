import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from ..crypto.asymmetric import generate_key_pair, deserialize_public_key
from cryptography.hazmat.primitives import serialization
from ..pki.pki_store import save_private_key, save_certificate, load_certificate, load_private_key
from ..logger import logger
from ..config import KEYSTORE_PATH

def create_subordinate_ca_certificate():
    
    # generar par de claves para la CA raiz
    private_key, public_key = generate_key_pair()

    # guardar la clave privada de la CA subordinada
    try:
        save_private_key("subordinate_ca", private_key)
    except Exception as e:
        logger.error(f"No se pudo guardar la clave privada de la CA subordinada: {e}")

    # cargar certificado y clave privada de la CA raíz para firmar la subordinada
    root_cert = load_certificate("root_ca")
    root_private = load_private_key("root_ca")
    if root_cert is None or root_private is None:
        raise RuntimeError("No se encuentra la CA raíz en el keystore. Cree la CA raíz primero.")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SeguriTicket"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Autoridad Certificadora Subordinada 1"),
    ])

    # creamos el certificado de la CA subordinada firmado por la CA raiz
    sub1_cert = x509.CertificateBuilder().subject_name(
        subject

    # el emisor es la CA raiz
    ).issuer_name(
        root_cert.subject

    # usa la clave publica de la CA subordinada que acaba de generarse
    ).public_key(
        public_key

    # numero de serie unico al azar
    ).serial_number(   
        x509.random_serial_number()

    # fechas de validez
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # 1 anyo de validez para el certificado
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    
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

    ).sign(
        private_key=root_private,
        algorithm=hashes.SHA256(),
    )

    # guardar en almacenamiento el certificado de la CA subordinada
    try:
        save_certificate("subordinate_ca", sub1_cert)
    except Exception as e:
        logger.error(f"No se pudo guardar el certificado de la CA subordinada: {e}")

    logger.info(f"CA subordinada creada en {KEYSTORE_PATH}")
    return private_key, sub1_cert

# funcion interna para cargar la clave y certificado de la CA subordinada (se usa en la firma de CSRs)
def _load_subordinate():
    key = load_private_key("subordinate_ca")
    cert = load_certificate("subordinate_ca")
    return key, cert


# funcion para firmar una solicitud de certificado (CSR) de un usuario (end entity) con la CA subordinada
def sign_csr(csr_pem: bytes | str, user_public_key_pem, validity_days: int = 30) -> bytes:
    #Recibe un CSR (bytes o str PEM), firma con la CA subordinada y devuelve el certificado PEM.

    #Se respetan las extensiones del CSR (certificate signing request) cuando sea posible y se fuerza BasicConstraints(ca=False).

    if csr_pem is None:
        raise ValueError("El CSR proporcionado es None.")

    # los certificados se manejan en formato PEM (bytes)
    # si se recibe como string se convierte a bytes
    if isinstance(csr_pem, str):
        csr_pem = csr_pem.encode("utf-8")

    # como se almacena en formato PEM, se convierte a objeto de certificado de la libreria
    csr = x509.load_pem_x509_csr(csr_pem)

    user_public_key = deserialize_public_key(user_public_key_pem)

    # se carga la clave publica y el certificado de la CA subordinada para firmar el nuevo certificado a emitir
    sub_key, sub_cert = _load_subordinate()

    # captacion de error si no se encuentra la informacion de la CA subordinada
    if sub_key is None or sub_cert is None:
        raise RuntimeError("No se ha encontrado la CA subordinada en el keystore.")


    # construccion del certificado a emitir basado en el CSR
    # se extraen los campos del CSR para usarlos en el builder y se firman con la CA subordinada
    builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        sub_cert.subject
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), 
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(private_key=sub_key, algorithm=hashes.SHA256())

    cert_pem = builder.public_bytes(serialization.Encoding.PEM)
    
    # guardar el certificado emitido en el keystore con su numero de serie
    # "ee" porque el tutorial lo llama "end entity"

    # sacamos una ruta unica para el certificado emitido usando su numero de serie
    cert_name = f"ee_cert_{builder.serial_number}"

    # guardamos el certificado emitido en el keystore o se capta error si hay
    try:
        save_certificate(cert_name, builder)
    except Exception:
        logger.debug("No se pudo persistir el certificado emitido en el keystore.")

    # se devuelve el certificado emitido en formato PEM (serializado)
    return cert_pem


# funcion para revocar un certificado por su numero de serie
# esta funcion no se usa directamente en el flujo del programa normal,
# pero se incluye para que tenga sentido la lista de certificados revocados, y se usara en las pruebas
def revoke_cert_by_serial(serial_number: int, reason=x509.ReasonFlags.unspecified, issuer_key_password: bytes | None = None):
    # import local para romper dependencia circular
    from .pki_certificate_actions import revoke_certificate

    issuer_name = "subordinate_ca"
    return revoke_certificate(issuer_name, cert_serial=serial_number, reason=reason, issuer_key_password=issuer_key_password)