from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives import hashes

from src.crypto.asymmetric import serialize_public_key
from ..config import KEYSTORE_PATH
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder
from .pki_store import KEYSTORE, _key_path, _cert_path, _crl_path, load_private_key, save_private_key, save_certificate, save_crl, load_certificate, load_crl, _get_crl_number
from ..logger import logger
import traceback


# funcionn para revocar un certificado dado su numero de serie y nombre del emisor
def revoke_certificate(issuer_name: str, cert_serial: int, reason: x509.ReasonFlags = x509.ReasonFlags.unspecified, issuer_key_password: bytes | None = None) -> x509.CertificateRevocationList:
    """
    cert_serial es el numero de serie del certificado a revocar
    issuer_key_password es para descifrar la clave privada del emisor del certificado donde se ha guardado
    """
    # cargar el certificado y la clave privada del emisor (issuer)
    issuer_cert = load_certificate(issuer_name)
    if issuer_cert is None:
        raise FileNotFoundError(f"Certificado del emisor {issuer_name} no encontrado.")
        
    issuer_private_key = load_private_key(issuer_name, password=issuer_key_password)
    if issuer_private_key is None:
        raise FileNotFoundError(f"Clave privada del emisor {issuer_name} no encontrada o contraseña incorrecta.")

    # cargar la CRL existente o crear una nueva si no existe
    # se busca nombre de la forma "<emisor>_crl"
    crl_name = issuer_name if issuer_name.endswith("_crl") else f"{issuer_name}_crl"
    crl = load_crl(crl_name)
    
    # si no hay CRL, la crea
    if crl is None:
        # la crl tiene como fecha de ultima actualizacion ahora mismo
        builder = CertificateRevocationListBuilder().last_update(
            datetime.datetime.now(datetime.timezone.utc)
        ).next_update(
            # proxima en una semana
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
        ).issuer_name(issuer_cert.subject)
        
        # inicializar el numero de CRL a 1 si la CRL no existe
        crl_number = 1
        
    else:
        # si hay CRL, la actualiza
        # reconstruir un nuevo builder conservando las entradas revocadas anteriores
        builder = CertificateRevocationListBuilder().issuer_name(crl.issuer).last_update(
            # actualizamos la fecha de ultima actualizacion a ahora mismo
            datetime.datetime.now(datetime.timezone.utc)
        ).next_update(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
        )
        
        # volver a anyadir los certificados revocados de la CRL antigua existente
        for revoked_cert in crl:
            builder = builder.add_revoked_certificate(revoked_cert)

        # incrementar el numero de CRL
        crl_number = (_get_crl_number(crl) or 0) + 1
    
    # revocar el certificado que buscabamos revocar con la funcion (anyadirlo a la lista)
    # counstruimos la entrada de certificado revocado
    revoked_cert_entry = RevokedCertificateBuilder().serial_number(
        cert_serial
    ).revocation_date(
        # fecha de revocacion es ahora
        datetime.datetime.now(datetime.timezone.utc)
    ).add_extension(
        # razon de revocacion (opcional)
        x509.CRLReason(reason), critical=False
    ).build()
    
    # construir la CRL final con el nuevo certificado revocado
    final_crl = builder.add_revoked_certificate(
        revoked_cert_entry
    ).add_extension(
        # numero de CRL (para versionado)
        x509.CRLNumber(crl_number), critical=False
    ).sign(
        # se firma con la clave privada del emisor
        private_key=issuer_private_key, algorithm=hashes.SHA256()
    )
    
    # guardar la nueva CRL usando el nombre de la forma emisor + "_crl"
    save_crl(crl_name, final_crl)
    
    return final_crl


# funcion para devolver en una lista todos los certificados en el keystore
def list_certificates() -> dict:
    # crear un diccionario de certificados, donde la clave es el nombre del certificado en el keystore
    certs = {}
    # busca en todos los ficheros del keystore que terminen en _cert.pem
    for p in KEYSTORE.glob("*_cert.pem"):
        # extrae el nombre del certificado sin el sufijo del nombre del fichero
        name = p.name.rsplit("_cert.pem", 1)[0]
        try:
            # se carga el certificado y se anyade al diccionario con clave el nombre del propietario del certificado
            certs[name] = x509.load_pem_x509_certificate(p.read_bytes())
        except Exception:
            continue
    # devolver el diccionario de certificados encontrados en keystore
    return certs


# funcion para buscar el nombre del certificado en el keystore dado un objeto certificado
def find_certificate_name(cert: x509.Certificate) -> str | None:
    # buscamos en la lista de certificados del keystore
    for name, c in list_certificates().items():
        try:
            # si encontramos coincidencia de huella calculada con SHA256, devolvemos el nombre que tiene en el keystore
            if c.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256()):
                return name
        except Exception:
            continue
    # devuelve None si no se encuentra ningun certificado coincidente
    return None


# funcion parabuscar un certificado por su clave publica en el keystore
def find_certificate_for_public_key(public_key) -> x509.Certificate | None:
    try:
        target_pub_key = serialize_public_key(public_key)
    except Exception:
        return None
    # recorrer cada certificado en el keystore
    for cert in list_certificates().values():
        try:
            # serializar la clave publica de cada certificado a un formato estandar para poder comparar
            public_key_pem = serialize_public_key(cert.public_key())
            # si se encuentra un certificado cuya clave publica coincide, es lo que buscamos y se devuelve
            if public_key_pem == target_pub_key:
                return cert
        except Exception:
            continue
    # devuelve None si no se encuentra ningun certificado con la clave publica dada
    return None

# IMPORTANTE: la verificacion temporal falla si los tiempos no son conscientes de zona horaria (naive)
# normalizar los tiempos del certificado a conscientes de zona horaria (tratar ingenuos/naive como UTC)
def _to_aware(dt: datetime.datetime) -> datetime.datetime:
    if dt is None:
        return dt
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.timezone.utc)


# verificar si un certificado es de confianza (PKI, cadena hasta la CA raiz)
def is_certificate_trusted(cert_pem: bytes) -> bool:
    """
    Verifica la cadena de confianza de un certificado, su validez temporal,
    y si ha sido revocado (a traves de la CRL de cada emisor)
    """

    # comprueba si el certificado esta serializado. Si lo esta, deserializa
    try:
        if isinstance(cert_pem, x509.Certificate):
            current = cert_pem
        else:
            current = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        logger.debug("fallo al cargar el certificado inicial: %s", e)
        return False


    # CARGAR certificados CA raiz y subordinada para la validacion de la cadena
    try:
        root_ca_cert = load_certificate("root_ca")
        sub_ca_cert = load_certificate("subordinate_ca")
        # si alguno no se encuentra, devuelve false
        if root_ca_cert is None or sub_ca_cert is None:
            return False

        # pasamos sujeto a string estandar para comparaciones
        ROOT_CA_SUBJECT = root_ca_cert.subject.rfc4514_string()
        SUB_CA_SUBJECT = sub_ca_cert.subject.rfc4514_string()
    except Exception as e:
        logger.debug("fallo al cargar los certificados CA: %s", e)
        return False

    # bucle para validar la cadena de abajo a arriba (acabando en la raiz)
    while True:
        # obtener sujeto e emisor como strings estandares para comparaciones
        try:
            current_subject = current.subject.rfc4514_string()
        except Exception:
            current_subject = str(current.subject)
        try:
            current_issuer = current.issuer.rfc4514_string()
        except Exception:
            current_issuer = str(current.issuer)


        # comprobar si el certificado es auto-firmado, es decir, si es LA RAIZ
        if current_issuer == current_subject:
            if current_subject == ROOT_CA_SUBJECT:
                # estamos en la raiz, cadena valida
                logger.debug("certificado auto-firmado de la raíz. Es confiable")
                break
            else:
                logger.debug("certificado auto-firmado desconocido (no es la raíz). No confiable")
                return False

        # VALIDEZ TEMPORAL
        now = datetime.datetime.now(datetime.timezone.utc)

        # IMPORTANTE: la verificacion temporal falla si los tiempos no son conscientes de zona horaria (naive)
        # normalizar los tiempos del certificado a conscientes de zona horaria (tratar ingenuos/naive como UTC)
        # (to_aware definido arriba, fuera de esta funcion)

        try:
            # conversion a conscientes de zona horaria
            not_before = _to_aware(current.not_valid_before_utc)
            not_after = _to_aware(current.not_valid_after_utc)
            # si el certificado no tiene fechas de validez o no es valido ahora (caducidad o no ha empezado validez), devuelve False
            if not_before is None or not_after is None:
                logger.debug("al certificado le faltan límites de validez")
                return False
            if not_before > now or not_after < now:
                logger.debug("el certificado está fuera del rango de validez %s %s ahora=%s", not_before, not_after, now)
                return False
        # captacion de errores
        except Exception as e:
            logger.debug("error al comprobar la validez temporal: %s", e)
            return False

        issuer_cert = None
        issuer_name = None

        # determinar el certificado del emisor actual en la cadena (AC subordinada o AC raiz)
        if current_issuer == SUB_CA_SUBJECT:
            issuer_cert = sub_ca_cert
            issuer_name = "subordinate_ca"
        elif current_issuer == ROOT_CA_SUBJECT:
            issuer_cert = root_ca_cert
            issuer_name = "root_ca"

        # captacion de errores: no se encuentra el emisor en la cadena
        if issuer_cert is None:
            logger.debug("Emisor del certificado no reconocido en la cadena: %s", current_issuer)
            return False

        # verificar que el emisor es CA (restricciones basicas) y tiene en extensiones del uso keyCertSign
        try:
            basic_constraints = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            key_usage = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            # si no es CA o no tiene keyCertSign, devuelve False
            if not basic_constraints.ca or not key_usage.key_cert_sign:
                return False
        except Exception as e:
            logger.debug("error al leer las extensiones del emisor: %s", e)
            return False

        # verificacion de firma
         # verificar firma de current con la clave publica del issuer_cert
        try:
            # verificar que se firmo con la clave privada correspondiente a la clave publica (ver documentacion arriba)
            # parametros en la documentacion oficial de cryptography.io:
            # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify
            issuer_cert.public_key().verify(
                current.signature,
                current.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                current.signature_hash_algorithm,
            )
        except Exception as e:
            logger.debug("excepción al verificar la firma: %s", e)
            return False

        # comprobaciones de CRL
        try:
            # cargar CRL usando el nombre emisor + "_crl"
            crl_name = issuer_name if issuer_name.endswith("_crl") else f"{issuer_name}_crl"
            crl = load_crl(crl_name)

            # si existe una lista de revocacion de certificados, comprobar si el certificado actual ha sido revocado
            if crl is not None:
                # verificar firma de CRL (ver arriba enlace a la documentacion)
                issuer_cert.public_key().verify(crl.signature, crl.tbs_certlist_bytes, asym_padding.PKCS1v15(), getattr(crl, "signature_hash_algorithm", None))
                # buscar el certificado actual en la CRL por su numero de serie
                revoked = crl.get_revoked_certificate_by_serial_number(current.serial_number)
                # si existe en la lista, entonces esta revocado, devuelve False
                if revoked is not None:
                    return False
        # captacion de errores al comprobar CRL
        except Exception as e:
            logger.debug("excepción al comprobar CRL: %s", e)
            return False

        # avanzar en la cadena
        current = issuer_cert

    # si se llega hasta aqui, el certificado es de confianza (ha llegado a la raiz en el bucle y ha salido)
    return True
