import base64
import pytest

from src.sign import sign_service
from src.crypto.asymmetric import generate_key_pair, serialize_public_key
import unicodedata
from src.crypto.asymmetric import serialize_private_key
from src.auth import user_store


# prueba para firmar un ticket y verificar usando el kid incluido
def test_sign_ticket_and_kid_roundtrip(tmp_path, monkeypatch):
    # usar un keystore temporal para no ensuciar el repo
    monkeypatch.setattr(sign_service, "KEYSTORE_PATH", str(tmp_path / "keystore"))

    payload = {"ticket_id": "T1", "user": "Alice", "amount": 100}
    wrapper = sign_service.sign_ticket_payload(payload)

    assert "meta" in wrapper and "signature" in wrapper
    meta = wrapper["meta"]
    assert meta.get("kid") is not None

    # el kid debe coincidir con el calculado a partir de la clave pública emisora
    pub = sign_service.get_issuer_public_key()
    expected_kid = sign_service._compute_kid_from_public_key(pub)
    assert expected_kid == meta.get("kid")

    # verificación correcta
    assert sign_service.verify_ticket_signature(payload, wrapper) is True

    # manipular el payload debe invalidar la verificación
    tampered = dict(payload)
    tampered["amount"] = 101
    assert sign_service.verify_ticket_signature(tampered, wrapper) is False


# prueba para firmar una autorizacion de transferencia e incluir el kid
def test_sign_transfer_authorization_includes_kid_and_verifies(tmp_path):
    # generar par de claves para el propietario
    priv, pub = generate_key_pair()
    pub_pem = serialize_public_key(pub)

    wrapper = sign_service.sign_transfer_authorization(priv, "ticket-2", pub_pem)
    assert "meta" in wrapper and "signature" in wrapper and "payload" in wrapper

    kid = wrapper["meta"].get("kid")
    assert kid is not None

    expected = sign_service._compute_kid_from_public_key(priv.public_key())
    assert expected == kid

    # verificación correcta usando la clave pública del propietario
    owner_pub_pem = serialize_public_key(priv.public_key())
    assert sign_service.verify_transfer_authorization(wrapper, owner_pub_pem) is True

    # corromper la firma -> verificación fallida
    sig_b64 = wrapper["signature"]
    sig = bytearray(base64.b64decode(sig_b64))
    sig[0] ^= 0x01
    wrapper_tampered = dict(wrapper)
    wrapper_tampered["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    assert sign_service.verify_transfer_authorization(wrapper_tampered, owner_pub_pem) is False


# prueba para cargar o crear claves emisoras y escribir archivos kid
def test_load_or_create_issuer_key_writes_kid_files(tmp_path, monkeypatch):
    # keystore temporal
    monkeypatch.setattr(sign_service, "KEYSTORE_PATH", str(tmp_path / "keystore"))
    priv = sign_service.load_or_create_issuer_key()
    # paths
    kp = tmp_path / "keystore"
    priv_path = kp / "issuer_private.pem"
    pub_path = kp / "issuer_public.pem"
    assert priv_path.exists()
    assert pub_path.exists()
    # kid file should exist
    kid = sign_service._compute_kid_from_public_key(priv.public_key())
    pub_kid = kp / f"issuer_public_{kid}.pem"
    assert pub_kid.exists()


# prueba para firmar un ticket y verificar usando lookup por kid
def test_verify_ticket_signature_uses_kid_lookup(tmp_path, monkeypatch):
    # preparar keystore y firmar
    monkeypatch.setattr(sign_service, "KEYSTORE_PATH", str(tmp_path / "keystore"))
    payload = {"ticket_id": "TK", "user": "Bob"}
    wrapper = sign_service.sign_ticket_payload(payload)
    meta = wrapper["meta"]
    kid = meta.get("kid")
    assert kid is not None

    # sobrescribir issuer_public.pem con una clave distinta para forzar que la verificación
    other_priv, other_pub = generate_key_pair() 
    other_pub_pem = serialize_public_key(other_pub)
    kp = tmp_path / "keystore"
    (kp / "issuer_public.pem").write_text(other_pub_pem, encoding="utf-8")

    # la verificación debería seguir pasando porque lookup por kid encuentra issuer_public_{kid}.pem
    assert sign_service.verify_ticket_signature(payload, wrapper) is True


# prueba para firmar datos de usuario y verificar la firma
def test_sign_data_for_user_and_verify_data_signature(monkeypatch):
    # generar par y mockear user_store para devolver PEMs
    priv, pub = generate_key_pair()
    priv_pem = serialize_private_key(priv)
    pub_pem = serialize_public_key(pub)
    # sign_service imported the functions at module import time, so patch them on that module
    monkeypatch.setattr(sign_service, "get_user_private_key_pem", lambda u: priv_pem)
    monkeypatch.setattr(sign_service, "get_user_public_key_pem", lambda u: pub_pem)

    data = b"mensaje-para-firmar"
    sig = sign_service.sign_data_for_user("alice", data)
    assert isinstance(sig, (bytes, bytearray))
    ok = sign_service.verify_data_signature("alice", data, sig)
    assert ok is True
    # cambio de datos -> verificación falla
    assert sign_service.verify_data_signature("alice", data + b"x", sig) is False


# prueba para canonización y equivalencia Unicode en firmas de tickets
def test_canonicalization_unicode_equivalence(tmp_path, monkeypatch):
    # asegurar que formas Unicode distintas canonican al mismo resultado
    monkeypatch.setattr(sign_service, "KEYSTORE_PATH", str(tmp_path / "keystore"))
    s_nfc = "mañana"  # already composed
    s_nfd = unicodedata.normalize("NFD", s_nfc)
    payload_nfc = {"ticket_id": "u1", "user": s_nfc}
    payload_nfd = {"ticket_id": "u1", "user": s_nfd}

    wrapper = sign_service.sign_ticket_payload(payload_nfc)
    # verification with the NFD payload should succeed due to normalization
    assert sign_service.verify_ticket_signature(payload_nfd, wrapper) is True


# prueba para exigir meta['alg'] en firmas de tickets y autorizaciones de transferencia
def test_meta_alg_enforced_for_ticket_and_transfer(tmp_path, monkeypatch):
    # comprobar que meta['alg'] se exige y que la verificación falla si se manipula
    monkeypatch.setattr(sign_service, "KEYSTORE_PATH", str(tmp_path / "keystore"))

    payload = {"ticket_id": "ALG1", "user": "Eve"}
    wrapper = sign_service.sign_ticket_payload(payload)
    # comprobación base
    assert sign_service.verify_ticket_signature(payload, wrapper) is True

    # manipular el algoritmo declarado en meta debe hacer que la verificación falle
    tampered = dict(wrapper)
    tampered_meta = dict(wrapper["meta"]) if wrapper.get("meta") else {}
    tampered_meta["alg"] = "FAKE-ALG"
    tampered["meta"] = tampered_meta
    assert sign_service.verify_ticket_signature(payload, tampered) is False

    # ahora para autorizaciones de transferencia
    priv, pub = generate_key_pair()
    pub_pem = serialize_public_key(pub)
    tran = sign_service.sign_transfer_authorization(priv, "tkt-alg", pub_pem)
    owner_pub_pem = serialize_public_key(priv.public_key())
    assert sign_service.verify_transfer_authorization(tran, owner_pub_pem) is True

    tran_t = dict(tran)
    meta_t = dict(tran.get("meta", {}))
    meta_t["alg"] = "OTHER-ALG"
    tran_t["meta"] = meta_t
    assert sign_service.verify_transfer_authorization(tran_t, owner_pub_pem) is False
