from .pki_AC_root import create_root_ca_certificate
from .pki_AC_subordinate import create_subordinate_ca_certificate, sign_csr
from .pki_user import create_user_csr
from ..auth.user_store import get_user_public_key_pem

# funcion para inicializar la infraestructura de clave publica (PKI)
def initialize_pki():
    # crear la CA raiz
    create_root_ca_certificate()

    # crear la CA subordinada
    create_subordinate_ca_certificate()

# funcion para inicializar un usuario en la PKI
def initialize_user_in_pki(username: str, private_key) -> bytes:
    # crear la peticion de certificado para el usuario
    user_csr = create_user_csr(username, private_key)
    # la CA subordinada firma la CSR y emite el certificado para el usuario
    user_cert = sign_csr(user_csr, get_user_public_key_pem(username))
    # se devuelve el certificado emitido para el usuario
    return user_cert
