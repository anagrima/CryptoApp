import importlib
import logging
import os
import pytest
from os import urandom
from src.crypto.symmetric import generate_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from src.common.constants import ALGO_AES_GCM
import src.config as config


# prueba de cifrado y descifrado AES GCM (128 bits)
def test_aes_encrypt_decrypt_128_bits():
    key = generate_aes_key(128)
    assert len(key) * 8 == 128
    plaintext = b"mensaje secreto de prueba"
    enc = encrypt_aes_gcm(key, plaintext)
    assert "iv" in enc and "ciphertext" in enc
    pt = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"])
    assert pt == plaintext


# prueba de longitud de clave insuficiente
def test_aes_key_too_short_raises():
    with pytest.raises(ValueError):
        generate_aes_key(64)  # menor que el minimo configurado (normalmente 128)


# soporte de longitudes de clave validas
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_aes_key_lengths_supported(bits):
    k = generate_aes_key(bits)
    assert len(k) * 8 == bits


# la salida de encrypt incluye iv(12 bytes), ciphertext y aad (eco)
def test_encrypt_returns_iv_ct_aad_and_iv_len():
    key = generate_aes_key(128)
    enc = encrypt_aes_gcm(key, b"hola", aad=b"meta")
    assert set(enc.keys()) == {"iv", "ciphertext", "aad"}
    assert isinstance(enc["iv"], (bytes, bytearray)) and len(enc["iv"]) == 12
    assert isinstance(enc["ciphertext"], (bytes, bytearray))
    assert enc["aad"] == b"meta"


# roundtrip con y sin AAD, y tamaños variados
@pytest.mark.parametrize("msg,aad", [
    (b"", b""),
    (b"hi", b""),
    (b"hola mundo", b"cabecera"),
    (os.urandom(4096), b"AAD"),
])
def test_roundtrip_various_sizes_and_aad(msg, aad):
    key = generate_aes_key(256)
    enc = encrypt_aes_gcm(key, msg, aad=aad)
    dec = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=aad)
    assert dec == msg


# no determinismo: cifrar dos veces produce (iv, ct) distintos
def test_non_determinism_due_to_random_iv():
    key = generate_aes_key(128)
    m = b"texto"
    e1 = encrypt_aes_gcm(key, m, aad=b"x")
    e2 = encrypt_aes_gcm(key, m, aad=b"x")
    assert (e1["iv"], e1["ciphertext"]) != (e2["iv"], e2["ciphertext"])


# AAD incorrecto
def test_decrypt_with_wrong_aad_raises():
    key = generate_aes_key(128)
    m = b"secret"
    enc = encrypt_aes_gcm(key, m, aad=b"A")
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"B")


# clave incorrecta
def test_decrypt_with_wrong_key_raises():
    key1 = generate_aes_key(128)
    key2 = generate_aes_key(128)
    m = b"secret"
    enc = encrypt_aes_gcm(key1, m, aad=b"h")
    with pytest.raises(Exception):
        decrypt_aes_gcm(key2, enc["iv"], enc["ciphertext"], aad=b"h")


# manipular ciphertext o tag
def test_tamper_ciphertext_or_tag_raises():
    key = generate_aes_key(256)
    m = b"mensaje"
    enc = encrypt_aes_gcm(key, m, aad=b"a")
    ct = bytearray(enc["ciphertext"])
    # Flip en el cuerpo
    ct_body = bytes(ct[:-16] + bytes([ct[-16] ^ 0x01]) + ct[-15:]) if len(ct) >= 17 else bytes([ct[0] ^ 1]) + bytes(ct[1:])
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, enc["iv"], ct_body, aad=b"a")
    # Flip en el ultimo byte del tag (ultimos 16 bytes)
    ct_tag = bytes(ct[:-1] + bytes([ct[-1] ^ 0x01]))
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, enc["iv"], ct_tag, aad=b"a")


# IV de tamaño incorrecto
@pytest.mark.parametrize("bad_iv", [b"", b"short", os.urandom(8), os.urandom(16)])
def test_decrypt_with_bad_iv_size_raises(bad_iv):
    key = generate_aes_key(128)
    enc = encrypt_aes_gcm(key, b"data", aad=b"")
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, bad_iv, enc["ciphertext"], aad=b"")


# mensaje y AAD Unicode (UTF-8)
def test_unicode_message_and_aad_utf8():
    key = generate_aes_key(192)
    msg = "ñandú🙂 cifrado".encode("utf-8")
    aad = "cabecera-usuario-用户".encode("utf-8")
    enc = encrypt_aes_gcm(key, msg, aad=aad)
    dec = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=aad)
    assert dec == msg


# mensaje grande (1MB)
def test_large_message_roundtrip():
    key = generate_aes_key(256)
    msg = os.urandom(1_000_000)
    enc = encrypt_aes_gcm(key, msg, aad=b"A")
    dec = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"A")
    assert dec == msg


# generate_aes_key respeta el minimo configurado
def test_generate_aes_key_enforces_min_bits():
    min_bits = config.AES_KEY_MIN_BITS
    k = generate_aes_key(min_bits)
    assert len(k) * 8 == min_bits
    if min_bits >= 136:  # para que sea menor pero razonable
        with pytest.raises(Exception):
            generate_aes_key(min_bits - 8)

# E2E con distintas longitudes de clave (128/192/256)
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_aes_gcm_encrypt_decrypt_param_bits(bits):
    key = generate_aes_key(bits)
    pt = b"texto de prueba"
    enc = encrypt_aes_gcm(key, pt, aad=b"meta")
    assert isinstance(enc, dict)
    assert set(enc.keys()) == {"iv", "ciphertext", "aad"}
    # IV de 12 bytes en GCM
    assert isinstance(enc["iv"], (bytes, bytearray)) and len(enc["iv"]) == 12
    # AAD eco
    assert enc["aad"] == b"meta"
    # descifrado correcto
    dec = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"meta")
    assert dec == pt

# AAD incorrecto --> verificacion de autenticidad debe fallar y log warning
def test_aes_gcm_wrong_aad_raises_and_logs_warning(caplog):
    key = generate_aes_key(128)
    enc = encrypt_aes_gcm(key, b"mensaje", aad=b"correcto")
    with caplog.at_level(logging.WARNING):
        with pytest.raises(Exception):
            decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"equivocado")
    assert any("decrypt failed" in r.message.lower() for r in caplog.records)

# IV con longitud invalida --> validacion debe fallar (ensure_gcm_iv)
@pytest.mark.parametrize("bad_iv", [b"", b"short", os.urandom(8), os.urandom(16)])
def test_aes_gcm_wrong_iv_length_raises(bad_iv):
    key = generate_aes_key(128)
    enc = encrypt_aes_gcm(key, b"hola", aad=b"x")
    # reutilizamos ciphertext valido, pero pasamos IV invalido
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, bad_iv, enc["ciphertext"], aad=b"x")

# manipulacion del ciphertext --> fallo de autenticidad + log WARNING
def test_aes_gcm_tampered_ciphertext_detects_modification(caplog):
    key = generate_aes_key(256)
    enc = encrypt_aes_gcm(key, b"datos muy secretos", aad=b"aad")
    # corrompe un byte del ciphertext
    ct = bytearray(enc["ciphertext"])
    ct[0] ^= 0x01
    with caplog.at_level(logging.WARNING):
        with pytest.raises(Exception):
            decrypt_aes_gcm(key, enc["iv"], bytes(ct), aad=b"aad")
    assert any(ALGO_AES_GCM in r.message for r in caplog.records)

# logs INFO en exito de cifrado/descifrado (traza con algoritmo y bits)
def test_aes_gcm_logs_info_on_success(caplog):
    key = generate_aes_key(192)
    with caplog.at_level(logging.INFO):
        enc = encrypt_aes_gcm(key, b"payload", aad=b"A")
        dec = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"A")
        assert dec == b"payload"
    # mensajes informativos esperados
    assert any("encrypt" in r.message.lower() and ALGO_AES_GCM in r.message for r in caplog.records)
    assert any("decrypt" in r.message.lower() and f"key_bits={len(key)*8}" in r.message for r in caplog.records)

# tipos de salida coherentes (bytes)
def test_encrypt_returns_bytes_types():
    key = generate_aes_key(128)
    enc = encrypt_aes_gcm(key, b"x", aad=b"y")
    assert isinstance(enc["iv"], (bytes, bytearray))
    assert isinstance(enc["ciphertext"], (bytes, bytearray))
    assert isinstance(enc["aad"], (bytes, bytearray))

# mensajes grandes + AAD no vacio (regresion de rendimiento/segmentacion)
def test_aes_gcm_large_message_with_aad():
    key = generate_aes_key(256)
    msg = os.urandom(1_000_000)  # 1 MB
    enc = encrypt_aes_gcm(key, msg, aad=b"meta-larga")
    out = decrypt_aes_gcm(key, enc["iv"], enc["ciphertext"], aad=b"meta-larga")
    assert out == msg


# prueba de reutilizacion de codigo OTP (ataque de repeticion)
def setup_module(module):
    # Carga limpia del módulo para evitar efectos de otros tests
    global sms
    sms = importlib.import_module("src.auth.short_message_service")
    # Asegurar que existe logger y caché limpia
    if not hasattr(sms, "logger"):
        import logging as _logging
        sms.logger = _logging.getLogger("sms")
    sms._OTP_CACHE = {}

def test_otp_replay_attack_prevented(caplog):
    username = "victima"
    code = "424242"
    # preparar la entrada inicial (code + attempts)
    sms._OTP_CACHE[username] = {"code": code, "attempts": 0}
    # primera verificacion: exito
    with caplog.at_level(logging.INFO):
        assert sms.verify_otp(username, code) is True
    assert any("OTP correcto" in r.message for r in caplog.records)
    # tras el exito la entrada debe haberse eliminado (no se puede reutilizar el codigo)
    assert username not in sms._OTP_CACHE
    # limpiar logs
    caplog.clear()
    # simular reutilizacion del mismo codigo (replay)
    with caplog.at_level(logging.INFO):
        reused_result = sms.verify_otp(username, code)
    assert reused_result is False
    # debe loguear que no hay codigo para el usuario
    assert any("Intento fallido" in r.message or "OTP" in r.message for r in caplog.records) or caplog.records == []

def test_decrypt_with_truncated_ciphertext_raises():
    """Si se recorta el ciphertext (p. ej. falta parte del tag), debe fallar."""
    key = generate_aes_key(256)
    msg = b"mensaje para truncar"
    enc = encrypt_aes_gcm(key, msg, aad=b"aad")
    # truncamos los últimos bytes (posible pérdida de tag)
    if len(enc["ciphertext"]) <= 8:
        pytest.skip("ciphertext demasiado corto para truncar en este entorno")
    truncated = enc["ciphertext"][:-8]
    with pytest.raises(Exception):
        decrypt_aes_gcm(key, enc["iv"], truncated, aad=b"aad")


def test_encrypt_accepts_bytearray_and_decrypt_accepts_bytearray_inputs():
    """Comprobación de que bytearray funciona tanto en encrypt como en decrypt."""
    key = generate_aes_key(128)
    pt = bytearray(b"texto en bytearray")
    enc = encrypt_aes_gcm(key, bytes(pt), aad=b"meta")  # encrypt normalmente espera bytes
    # pasar bytearray al decrypt (IV y ciphertext) debería funcionar
    iv_ba = bytearray(enc["iv"])
    ct_ba = bytearray(enc["ciphertext"])
    out = decrypt_aes_gcm(key, iv_ba, ct_ba, aad=b"meta")
    assert out == bytes(pt)


def test_decrypt_accepts_memoryview_inputs():
    """Verifica que memoryview sobre los buffers también es aceptado."""
    key = generate_aes_key(192)
    pt = b"texto a memoryview"
    enc = encrypt_aes_gcm(key, pt, aad=b"x")
    iv_mv = memoryview(enc["iv"])
    ct_mv = memoryview(enc["ciphertext"])
    out = decrypt_aes_gcm(key, iv_mv, ct_mv, aad=b"x")
    assert out == pt


def test_generate_aes_key_invalid_type_raises():
    """Passar un tipo no entero o inválido a generate_aes_key debe producir excepción."""
    with pytest.raises(Exception):
        generate_aes_key("128")   # string no válido
    with pytest.raises(Exception):
        generate_aes_key(None)    # None no válido
    # números no estándar
    with pytest.raises(Exception):
        generate_aes_key(0)
    with pytest.raises(Exception):
        generate_aes_key(-128)