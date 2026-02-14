# operaciones de firma en la aplicacion

import json
import unicodedata
import base64
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import getpass
from typing import Optional
import os

from ..crypto.signature import sign_data, verify_signature
from ..crypto.asymmetric import (
    deserialize_private_key,
    deserialize_public_key,
    generate_key_pair,
    serialize_private_key,
    serialize_public_key,
)
from ..auth.user_store import get_user_private_key_pem, get_user_public_key_pem
from ..logger import logger
from ..config import KEYSTORE_PATH
from ..common.constants import ALGO_RSA_PSS_SHA256
from cryptography.hazmat.primitives import serialization
from ..pki.pki_store import load_certificate
from ..pki.pki_certificate_actions import is_certificate_trusted, find_certificate_for_public_key

# recupera la clave privada de un usuario, la deserializa y firma los datos
def sign_data_for_user(username: str, data_to_sign: bytes) -> bytes:
    # recuperar la clave privada del usuario (PEM string)
    private_key_pem = get_user_private_key_pem(username)
    if not private_key_pem: # si no se encuentra la clave --> registrar y lanzar error
        logger.error(f"No se encontró la clave privada para el usuario {username}.")
        raise ValueError("Clave privada no encontrada.")
    # intentar firmar los datos
    try:
        # deserializar la clave privada
        private_key = deserialize_private_key(private_key_pem)
        # generar la firma digital
        signature = sign_data(private_key, data_to_sign)
        return signature
    # capturar errores durante el proceso de firma
    except Exception as e:
        logger.error(f"Error al firmar datos para el usuario {username}: {e}")
        return None

def verify_data_signature(username: str, data: bytes, signature: bytes) -> bool:
    # recuperar la clave publica del usuario (PEM string)
    public_key_pem = get_user_public_key_pem(username)
    if not public_key_pem: # si no se encuentra la clave --> registrar y lanzar error
        logger.warning(f"No se encontró la clave pública para el usuario {username}.")
        return False
    # intentar verificar la firma
    try:
        # deserializar la clave pública
        public_key = deserialize_public_key(public_key_pem)
        # verificar la firma digital
        is_valid = verify_signature(public_key, data, signature)
        return is_valid
    # capturar errores durante el proceso de verificación
    except Exception as e:
        logger.error(f"Error al verificar la firma para el usuario {username}: {e}")
        return False


# helpers para firmar tickets de emision y autorizaciones de transferencia
def _canonical_json(obj: dict) -> bytes:
    def _normalize(o):
        # normalizar cadenas Unicode a NFC
        if isinstance(o, str):
            # normalizar a la forma compuesta NFC para consistencia
            return unicodedata.normalize("NFC", o)
        if isinstance(o, dict):
            # normalizar claves y valores recursivamente
            new = {}
            for k, v in o.items():
                nk = unicodedata.normalize("NFC", k) if isinstance(k, str) else k
                new[nk] = _normalize(v)
            return new
        if isinstance(o, list):
            # normalizar elementos recursivamente
            return [_normalize(i) for i in o]
        if isinstance(o, tuple):
            # normalizar elementos recursivamente
            return tuple(_normalize(i) for i in o)
        return o

    # serialización determinista: keys ordenadas, sin espacios innecesarios
    normalized = _normalize(obj)
    return json.dumps(normalized, separators=(",",":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _keystore_paths() -> tuple[Path, Path]:
    # asegurar que el keystore existe
    kp = Path(KEYSTORE_PATH)
    kp.mkdir(parents=True, exist_ok=True)
    priv = kp / "issuer_private.pem"
    pub = kp / "issuer_public.pem"
    return priv, pub


def _logs_dir() -> Path:
    # asegurar que el directorio de logs existe
    p = Path("logs_sign")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _append_sign_log(entry: dict) -> None:
    # agrega una entrada al log de firmas
    ln = json.dumps(entry, ensure_ascii=False, indent=2)
    logfile = _logs_dir() / "signatures.log"
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(ln + "\n\n")


def _hash_bytes(b: bytes) -> str:
    # calcula el SHA-256 hash de los bytes y devuelve el hex digest
    return hashlib.sha256(b).hexdigest()


def _compute_kid_from_public_key(public_key) -> str:
    # calcula el kid (identificador de clave) a partir de la clave pública
    try:
        # obtener el SubjectPublicKeyInfo en formato DER
        spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki).hexdigest()
    except Exception:
        # En caso de fallo, devolver None-like string para evitar romper flujo
        return None


def _compute_kid_from_pem(pem: str) -> str:
    # calcula el kid a partir de un PEM de clave pública
    pub = deserialize_public_key(pem)
    return _compute_kid_from_public_key(pub)


def get_issuer_public_key_by_kid(kid: str):
    # recupera la clave pública del emisor buscando por kid
    if not kid:
        return None
    kp = Path(KEYSTORE_PATH)
    if not kp.exists():
        return None
    # buscar entre todos los PEMs en el keystore
    for p in kp.glob("*.pem"):
        try:
            # leer el PEM
            pem = p.read_text(encoding="utf-8")
        except Exception:
            continue
        try:
            # deserializar la clave pública
            pub = deserialize_public_key(pem)
        except Exception:
            # no es una clave pública válida (p. ej. private PEM), saltar
            continue
        try:
            # calcular el kid a partir de la clave pública
            k = _compute_kid_from_public_key(pub)
        except Exception:
            continue
        if k == kid:
            # encontrado el kid coincidente
            return pub
    return None # devolver None si no se encuentra


def append_sign_log(entry: dict) -> None:
    # agrega una entrada al log de firmas
    _append_sign_log(entry)


def load_or_create_issuer_key(password: bytes | None = None):
    # carga la clave emisora desde el keystore o la crea si no existe
    priv_path, pub_path = _keystore_paths()
    # si no se pasó password, intentar usar la contraseña global cargada desde env/setter
    global _ISSUER_PASSWORD
    if password is None:
        password = _ISSUER_PASSWORD
    # si ya existe --> cargarla
    if priv_path.exists():
        pem = priv_path.read_text(encoding="utf-8")
        # Intentar deserializar con la contraseña (si hay una)
        if password is not None:
            try:
                return deserialize_private_key(pem, password=password)
            except Exception:
                # si falla con password proporcionada -> no podemos usar la clave
                raise RuntimeError("No se pudo cargar la clave emisora con la contraseña proporcionada.")
        # si no hay contraseña proporcionada, intentar deserializar sin contraseña
        try:
            priv = deserialize_private_key(pem)
            # Si esto funciona, la clave está almacenada sin cifrar: esto NO está permitido
            raise RuntimeError("La clave emisora está almacenada sin cifrar. Debe configurarse una contraseña (ISSUER_KEY_PASSWORD) para protegerla.")
        except Exception:
            # si no se puede deserializar sin password, significa que está cifrada y necesitamos la contraseña
            raise RuntimeError("La clave emisora está cifrada: proporcione la contraseña mediante ISSUER_KEY_PASSWORD o set_issuer_password().")

    # crear nuevo par y guardarlo
    if password is None:
        raise RuntimeError("Para crear la clave emisora es obligatorio proporcionar una contraseña (ISSUER_KEY_PASSWORD).")
    private_key, public_key = generate_key_pair()
    priv_pem = serialize_private_key(private_key, password=password)
    pub_pem = serialize_public_key(public_key)
    try:
        priv_path.write_text(priv_pem, encoding="utf-8")
        pub_path.write_text(pub_pem, encoding="utf-8")
        kid = _compute_kid_from_pem(pub_pem)
        # además de la copia estándar --> guardar una copia nombrada por kid
        try:
            if kid:
                pub_kid_path = priv_path.parent / f"issuer_public_{kid}.pem"
                pub_kid_path.write_text(pub_pem, encoding="utf-8")
        except Exception:
            # no interrumpir si no se puede escribir la copia por kid
            pass
        logger.info(f"Se creó nueva clave emisora en {priv_path} (kid={kid})")
    except Exception as e:
        logger.error(f"No se pudo guardar la clave emisora: {e}")
    return private_key


def get_issuer_public_key():
    # recupera la clave pública del emisor desde el keystore
    priv_path, pub_path = _keystore_paths()
    if pub_path.exists():
        pem = pub_path.read_text(encoding="utf-8")
        return deserialize_public_key(pem)
    # si no existe la public key pero existe la private --> derivar y guardar
    if priv_path.exists():
        priv_pem = priv_path.read_text(encoding="utf-8")
        # intentar deserializar con la contraseña configurada
        global _ISSUER_PASSWORD
        if _ISSUER_PASSWORD is not None:
            try:
                priv = deserialize_private_key(priv_pem, password=_ISSUER_PASSWORD)
            except Exception:
                raise RuntimeError("No se pudo deserializar la clave emisora con la contraseña configurada.")
        else:
            # intentar sin contraseña: si funciona, la clave está sin cifrar (no permitido)
            try:
                priv = deserialize_private_key(priv_pem)
                raise RuntimeError("La clave emisora está almacenada sin cifrar. Configure ISSUER_KEY_PASSWORD para protegerla.")
            except Exception:
                raise RuntimeError("La clave emisora está cifrada: configure ISSUER_KEY_PASSWORD o set_issuer_password().")
        pub_pem = serialize_public_key(priv.public_key())
        try:
            # guardar la clave pública derivada
            pub_path.write_text(pub_pem, encoding="utf-8")
        except Exception:
            pass
        return priv.public_key()
    return None


def sign_ticket_payload(payload: dict, issuer_password: bytes | None = None) -> dict:
    # firma el payload del ticket con la clave emisora y devuelve el wrapper de firma
    # canonicalizar payload
    data = _canonical_json(payload)
    # cargar o crear clave emisora (si no se pasa issuer_password se usará el valor global)
    private_key = load_or_create_issuer_key(password=issuer_password)
    sig = sign_data(private_key, data)
    sig_b64 = base64.b64encode(sig).decode("ascii")
    # incluir identificador de clave para facilitar verificación y rotación
    kid = None
    try:
        kid = _compute_kid_from_public_key(private_key.public_key())
    except Exception:
        kid = None
    meta = {
        "alg": ALGO_RSA_PSS_SHA256,
        "ver": "1",
        "kid": kid,
    }
    wrapper = {"meta": meta, "signature": sig_b64}
    # registrar la firma en logs_sign
    try:
        _append_sign_log({
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "issue",
            "actor": "issuer",
            "ticket_id": payload.get("ticket_id"),
            "payload_hash": _hash_bytes(_canonical_json(payload)),
            "signature": sig_b64,
            "meta": meta,
            "key_size": getattr(private_key, "key_size", None),
            "kid": kid,
        })
    except Exception:
        # no interrumpir el flujo por fallo en el logging
        pass
    return wrapper


def verify_ticket_signature(payload: dict, signature_wrapper: dict) -> bool:
    # verifica la firma emisora sobre el payload dado el wrapper de firma
    try:
        # Preferir buscar la clave por 'kid' si viene en el wrapper
        meta = signature_wrapper.get("meta", {}) if signature_wrapper else {}
        # validar algoritmo declarado en meta (si viene) para evitar ambigüedad
        alg = meta.get("alg") if isinstance(meta, dict) else None
        if alg and alg != ALGO_RSA_PSS_SHA256:
            logger.warning(f"Algoritmo de firma no soportado en wrapper: {alg}")
            return False
        kid = meta.get("kid") if isinstance(meta, dict) else None
        pub = None
        if kid:
            pub = get_issuer_public_key_by_kid(kid)
            if pub is None:
                logger.warning(f"No se encontró clave emisora con kid={kid}; intentando clave por defecto")
        if pub is None:
            pub = get_issuer_public_key()
        if pub is None:
                logger.error("Clave pública del emisor no disponible para verificación")
                return False
        sig_b64 = signature_wrapper.get("signature")
        if not sig_b64:
            return False
        sig = base64.b64decode(sig_b64)
        data = _canonical_json(payload)
        # si no hay CA raíz en el keystore, mantener comportamiento previo (aceptar clave pública directa)
        try:
            if load_certificate("root_ca") is not None:
                # verificar que existe un certificado asociado y que es de confianza
                cert = find_certificate_for_public_key(pub)
                if cert is None:
                    logger.warning("No se encontró certificado X.509 asociado a la clave emisora; rechazo de la verificación.")
                    return False
                if not is_certificate_trusted(cert):
                    logger.warning("Certificado de la clave emisora no es de confianza o no forma parte de la cadena hasta la CA raíz.")
                    return False
        except Exception as e:
            logger.error(f"Error al validar certificado de la clave emisora: {e}")
            return False

        return verify_signature(pub, data, sig)
    except Exception as e:
        logger.error(f"Error al verificar firma de ticket: {e}")
        return False


def sign_transfer_authorization(private_key, ticket_id: str, new_owner_pubkey_pem: str,
                                timestamp: str | None = None, private_key_password: Optional[bytes] = None) -> dict:
    # firma una autorización de transferencia para un ticket dado
    payload = {
        "ticket_id": ticket_id,
        "new_owner_pubkey": new_owner_pubkey_pem,
    }
    if timestamp:
        payload["timestamp"] = timestamp
    # si la clave viene en formato PEM, deserializarla usando la contraseña si se proporciona
    if isinstance(private_key, (str, bytes)):
        pem = private_key.decode("utf-8") if isinstance(private_key, bytes) else private_key
        try:
            # intentar deserializar con la contraseña (puede ser None)
            priv_obj = deserialize_private_key(pem, password=private_key_password)
        except Exception as e:
            # si falla por falta de contraseña y estamos en modo interactivo, pedirla
            try:
                if private_key_password is None:
                    pwd = getpass.getpass("Introduce la contraseña de la clave privada: ")
                    priv_obj = deserialize_private_key(pem, password=pwd.encode("utf-8") if pwd else None)
                else:
                    raise
            except Exception:
                logger.error(f"No se pudo deserializar la clave privada PEM: {e}")
                raise
        private_key = priv_obj

    data = _canonical_json(payload)
    sig = sign_data(private_key, data)
    sig_b64 = base64.b64encode(sig).decode("ascii")
    # incluir kid del firmante
    signer_kid = None
    try:
        signer_kid = _compute_kid_from_public_key(private_key.public_key())
    except Exception:
        signer_kid = None

    wrapper = {"meta": {"alg": ALGO_RSA_PSS_SHA256, "ver": "1", "kid": signer_kid}, "signature": sig_b64, "payload": payload}
    # intentar loguear la creación de la autorización si es posible
    try:
        _append_sign_log({
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "create_transfer_authorization",
            "actor": None,
            "ticket_id": ticket_id,
            "payload": payload,
            "signature": sig_b64,
            "key_size": getattr(private_key, "key_size", None),
            "kid": signer_kid,
        })
    except Exception:
        pass
    return wrapper


def verify_transfer_authorization(wrapper: dict, owner_public_key_pem: str | None = None) -> bool:
    # verifica la autorización de transferencia usando la clave pública del propietario
    try:
        # validar algoritmo declarado en meta (si viene) para evitar ambigüedad
        meta = wrapper.get("meta", {}) if wrapper else {}
        alg = meta.get("alg") if isinstance(meta, dict) else None
        if alg and alg != ALGO_RSA_PSS_SHA256:
            logger.warning(f"Algoritmo de firma no soportado en transferencia: {alg}")
            return False
        if owner_public_key_pem is None:
            logger.error("No se proporcionó clave pública del propietario para verificar la autorización")
            return False
        pub = deserialize_public_key(owner_public_key_pem)
        sig_b64 = wrapper.get("signature")
        payload = wrapper.get("payload")
        if not sig_b64 or not payload:
            logger.debug("Wrapper de transferencia incompleto")
            return False
        sig = base64.b64decode(sig_b64)
        data = _canonical_json(payload)
        # si existe CA raíz -> exigir certificado y cadena de confianza, si no -> comportarse como antes
        try:
            if load_certificate("root_ca") is not None:
                cert = find_certificate_for_public_key(pub)
                if cert is None:
                    logger.warning("No se encontró certificado X.509 asociado a la clave del propietario; rechazo de la verificación de transferencia.")
                    return False
                if not is_certificate_trusted(cert):
                    logger.warning("Certificado del propietario no es de confianza o no forma parte de la cadena hasta la CA raíz.")
                    return False
        except Exception as e:
            logger.error(f"Error al validar certificado del propietario: {e}")
            return False

        return verify_signature(pub, data, sig)
    except Exception as e:
        logger.error(f"Error al verificar autorización de transferencia: {e}")
        return False


# Module-level issuer password handling
_ISSUER_PASSWORD: bytes | None = None

def set_issuer_password(pw: bytes) -> None:
    """Set the issuer key password (bytes). Call this at server startup.
    Prefer loading from secure env var `ISSUER_KEY_PASSWORD` (string -> UTF-8).
    """
    global _ISSUER_PASSWORD
    _ISSUER_PASSWORD = pw

def clear_issuer_password() -> None:
    global _ISSUER_PASSWORD
    _ISSUER_PASSWORD = None

def _load_issuer_password_from_env() -> None:
    v = os.environ.get("ISSUER_KEY_PASSWORD")
    if v is None:
        return
    try:
        set_issuer_password(v.encode("utf-8"))
    except Exception:
        # ignore if cannot encode
        pass

# intentar cargar la contraseña al importar el módulo
_load_issuer_password_from_env()
