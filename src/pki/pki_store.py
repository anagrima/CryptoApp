from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from ..config import KEYSTORE_PATH
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder
from ..crypto.asymmetric import deserialize_private_key, serialize_private_key

# crear el directorio del keystore si no existe
KEYSTORE = Path(KEYSTORE_PATH)
KEYSTORE.mkdir(parents=True, exist_ok=True)


# rutas para las claves en el keystore
def _key_path(name: str) -> Path:
    return KEYSTORE / f"{name}_key.pem"


# rutas para  certificados en el keystore
def _cert_path(name: str) -> Path:
    return KEYSTORE / f"{name}_cert.pem"

# rutas para CRL en el keystore
def _crl_path(name: str) -> Path:
    return KEYSTORE / f"{name}_crl.pem"


# funcion para guardar y cargar claves y certificados
def save_private_key(name: str, private_key, password: bytes | None = None) -> Path:
    path = _key_path(name)
    # serializamos la clave privada en formato PEM, .encode para pasarlo a bytes en vez de string
    private_key_pem = serialize_private_key(private_key, password=password).encode('utf-8')
    path.write_bytes(private_key_pem)
    return path


# cargar clave privada desde el keystore
def load_private_key(name: str, password: bytes | None = None):
    path = _key_path(name)
    if not path.exists():
        return None
    data = path.read_bytes()
    return load_pem_private_key(data, password=password)

# guardar certificado en el keystore
def save_certificate(name: str, cert: x509.Certificate) -> Path:
    path = _cert_path(name)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def save_crl(name: str, crl: x509.CertificateRevocationList) -> Path:
    path = _crl_path(name)
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return path

# cargar certificado desde el keystore
def load_certificate(name: str) -> x509.Certificate | None:
    path = _cert_path(name)
    if not path.exists():
        return None
    data = path.read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_crl(name: str) -> x509.CertificateRevocationList | None:
    path = _crl_path(name)
    if not path.exists():
        return None
    data = path.read_bytes()
    return x509.load_pem_x509_crl(data)


def _get_crl_number(crl: x509.CertificateRevocationList) -> int | None:
    try:
        ext = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER)
        return int(ext.value.crl_number)
    except Exception:
        return None
