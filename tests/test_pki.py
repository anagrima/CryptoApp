import pytest
import shutil
from pathlib import Path
from src.pki import pki_store
from src.pki.pki_init import initialize_pki, initialize_user_in_pki
from src.pki.pki_AC_subordinate import revoke_cert_by_serial
from src.pki.pki_certificate_actions import is_certificate_trusted, revoke_certificate
from src.pki.pki_store import load_certificate, _key_path, _cert_path, _crl_path
from src.crypto.asymmetric import generate_key_pair, serialize_public_key

from src.config import KEYSTORE_PATH 
from src.auth import user_store
import datetime
from cryptography import x509


@pytest.fixture(scope="session")
def user_key_pair():
    """Genera un par de claves para un usuario de prueba."""
    return generate_key_pair()


@pytest.fixture(scope="function")
def setup_teardown_keystore(tmp_path_factory, monkeypatch):
    """
    para crear un KEYSTORE temporal en cada modulo de prueba
    y limpiar el almacenamiento de KEYSTORE una vez terminadas las pruebas
    Usa 'monkeypatch' para sobrescribir la ruta real de KEYSTORE_PATH
    """
    # crear el directorio temporal para keystore en la prueba
    temp_dir = tmp_path_factory.mktemp("keystore_pki_test")

    pki_store.KEYSTORE = Path(str(temp_dir))
    pki_store.KEYSTORE.mkdir(parents=True, exist_ok=True)
    
    # sobrescribir la ruta en el modulo de configuracion
    # con esto los modulos que usen KEYSTORE_PATH usaran este path temporal
    temp_dir_str = str(temp_dir)

    # parchear la fuente de verdad (src.config)
    monkeypatch.setattr("src.config.KEYSTORE_PATH", temp_dir_str)

    # parchear pki_user.py (para guardar el CSR)
    monkeypatch.setattr("src.pki.pki_user.KEYSTORE_PATH", temp_dir_str)

    # re-asignar el objeto Path en pki_store.py
    monkeypatch.setattr("src.pki.pki_store.KEYSTORE", Path(temp_dir_str))
    
    # yield: Ejecutar las pruebas
    yield temp_dir
    
    # limpiar el directorio temporal al finalizar las pruebas
    #shutil.rmtree(temp_dir)

    if Path(temp_dir).exists():
        shutil.rmtree(temp_dir)


@pytest.fixture(scope="function")
def initialized_pki(setup_teardown_keystore):
    """
    Inicializa la PKI (Root CA y Subordinate CA) una sola vez por modulo
    """
    initialize_pki()
    return setup_teardown_keystore

# test para verificar que la inicializacion de la PKI crea las CAs correctamente: claves y certificados
def test_pki_initialization_creates_certs(initialized_pki):

    # usa fixture initialized_pki
    keystore_path = initialized_pki
    
    # comprobar que los archivos de claves y certificados existen para AC raiz y subordinada
    assert Path(keystore_path / "root_ca_key.pem").exists()
    assert Path(keystore_path / "root_ca_cert.pem").exists()
    assert Path(keystore_path / "subordinate_ca_key.pem").exists()
    assert Path(keystore_path / "subordinate_ca_cert.pem").exists()

    # comprobar que el certificado se puede cargar (usa funcion load_certificate de pki_store)
    root_cert = load_certificate("root_ca")
    sub_cert = load_certificate("subordinate_ca")
    # verificar que los certificados no son None
    assert root_cert is not None
    assert sub_cert is not None
    
    # comprobar la correspondencia de sujetos y emisores de los certificados
    assert root_cert.issuer == root_cert.subject
    assert sub_cert.issuer == root_cert.subject
    
    # comprobar extension critica: BasicConstraints ca=True, es decir, que se marcan como Autoridades Certificadoras en los certificados
    root_basic_constraints = root_cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
    sub_basic_constraints = sub_cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
    assert root_basic_constraints.ca is True
    assert sub_basic_constraints.ca is True


# test para comprobar que un usuario se inicializa adecuadamente en la PKI
def test_user_inicialization_creates_valid_cert(initialized_pki, user_key_pair, monkeypatch):
    """
    Flujo esperado:
    1. generacion de CSR (pki_user.create_user_csr())
    2. firma por la CA subordinada (pki_AC_subordinate.sign_csr())
    3. Validacion de la cadena de confianza (pki_certificate_actions.is_certificate_trusted())
    """
    # datos del usuario de prueba
    username = "testuser"
    private_key, public_key = user_key_pair

    # simular la dependencia de user_store.get_user_public_key_pem
    # al crear la CSR, se busca la clave publica del usuario
    public_key_pem = serialize_public_key(public_key)
    # 2. Parchear la función get_user_public_key_pem en el módulo pki_user
    #    Esto arregla la llamada DENTRO de create_user_csr.
    monkeypatch.setattr("src.pki.pki_user.get_user_public_key_pem", lambda x: public_key_pem)

    # 3. Parchear la función get_user_public_key_pem en el módulo pki_init
    #    Esto arregla la llamada DENTRO de initialize_user_in_pki
    #    (linea 19: user_cert = sign_csr(user_csr, get_user_public_key_pem(username)))
    monkeypatch.setattr("src.pki.pki_init.get_user_public_key_pem", lambda x: public_key_pem)

    # inicializar al usuario en la PKI (Crea CSR y lo firma la Subordinate CA)
    user_cert_pem = initialize_user_in_pki(username, private_key)
    user_cert = x509.load_pem_x509_certificate(user_cert_pem)
    
    # comprobar que se genero un certificado (el retorno no es NOne) y se guardo adecuadamente en el keystore
    assert user_cert is not None
    assert _cert_path(f"ee_cert_{user_cert.serial_number}").exists()

    # comprobar la cadena de confianza (usuario -> Subordinada -> Raiz/Root)

    # el certificado del usuario debe ser emitido por la Subordinate CA, asi que cargamos el certificado de la AC subordinada
    sub_ca_cert = load_certificate("subordinate_ca")
    # comprobar que el emisor del certificado del usuario coincide con el sujeto de la AC subordinada
    assert user_cert.issuer == sub_ca_cert.subject

    # validar la cadena hasta la raiz
    is_valid = is_certificate_trusted(user_cert_pem)
    assert is_valid is True, "La validación de un certificado recién emitido debería ser exitosa."


# test para validar la revolcacion de un certificado y su impacto en la validacion de la cadena
def test_certificate_revocation_invalidates_chain(initialized_pki, user_key_pair, monkeypatch):
    """
    Verifica la revocacion:
    1. se inscribe un usuario
    2. se revoca el certificado
    3. la validacion de cadena debe fallar
    """
    # datos del usuario de prueba cuyo certificado revocaremos
    username = "revoked_user"
    # nuevo par de claves para este usuario
    private_key, public_key = generate_key_pair() 

    # simulacion de get_user_public_key_pem para este nuevo usuario
    public_key_pem = serialize_public_key(public_key)
    # parchear la funcion get_user_public_key_pem en el modulo pki_user
    monkeypatch.setattr("src.pki.pki_user.get_user_public_key_pem", lambda x: public_key_pem)

    # parchear la funcion get_user_public_key_pem en el modulo pki_init
    monkeypatch.setattr("src.pki.pki_init.get_user_public_key_pem", lambda x: public_key_pem)
    
    # meter al usuario en la PKI y obtener su certificado
    user_cert_pem = initialize_user_in_pki(username, private_key)
    user_cert = x509.load_pem_x509_certificate(user_cert_pem)
    # tomamos el numero de serie del certificado del nuevo usuario para revocarlo
    serial_number = user_cert.serial_number
    
    # verificacion en la cadena antes de la revocacion
    assert is_certificate_trusted(user_cert_pem) is True

    # REVOCAR el certificado (usando la CA subordinada como emisor del certificado, solo hemos hecho una CA subordinada)
    revoke_certificate("subordinate_ca", serial_number)
    
    # comprobar que se ha creado la CRL o se ha actualizado
    assert _crl_path("subordinate_ca_crl").exists()
    
    # validar de nuevo el certifiado en la cadena
    # DEBE FALLAR LA VALIDACION ahora que se ha revocado el certificado
    is_valid_after_revocation = is_certificate_trusted(user_cert_pem)
    # assert que la validacion sea FALSA
    assert is_valid_after_revocation is False, "La validación debe fallar después de la revocación."
