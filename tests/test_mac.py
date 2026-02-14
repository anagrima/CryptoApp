# test para mac.py
import pytest
import importlib
from src.crypto.mac import generate_hmac_key, compute_hmac, verify_hmac


# prueba de generacion y verificacion HMAC
def test_hmac_generate_and_verify():
    key = generate_hmac_key(256)
    assert len(key) * 8 == 256
    msg = b"mensaje para hmac"
    tag = compute_hmac(key, msg)
    assert isinstance(tag, (bytes, bytearray))
    assert verify_hmac(key, msg, tag) is True


# prueba de verificacion HMAC falla al modificar mensaje
def test_hmac_verification_fails_on_tamper():
    key = generate_hmac_key(256)
    msg = b"mensaje original"
    tag = compute_hmac(key, msg)
    # modificar mensaje provoca verificación false
    assert verify_hmac(key, b"mensaje modificado", tag) is False


# determinismo y longitud del tag
def test_hmac_is_deterministic_and_tag_length():
    key = generate_hmac_key(256)
    msg = b"same message"
    t1 = compute_hmac(key, msg)
    t2 = compute_hmac(key, msg)
    assert t1 == t2
    assert isinstance(t1, (bytes, bytearray))
    assert len(t1) == 32  # SHA-256 -> 32 bytes


# modificar tag debe fallar
def test_hmac_verification_fails_on_tag_tamper():
    key = generate_hmac_key(256)
    msg = b"msg"
    tag = compute_hmac(key, msg)
    bad = bytearray(tag)
    bad[-1] ^= 0x01
    assert verify_hmac(key, msg, bytes(bad)) is False


# modificar clave debe fallar
def test_hmac_verification_fails_on_wrong_key():
    key1 = generate_hmac_key(256)
    key2 = generate_hmac_key(256)
    msg = b"msg"
    tag = compute_hmac(key1, msg)
    assert verify_hmac(key2, msg, tag) is False


# casos limite

#  mensaje vacio
def test_hmac_empty_message():
    key = generate_hmac_key(256)
    tag = compute_hmac(key, b"")
    assert verify_hmac(key, b"", tag) is True

# datos binarios/Unicode
def test_hmac_unicode_message_utf8():
    key = generate_hmac_key(256)
    msg = "ñandú🙂 usuario".encode("utf-8")
    tag = compute_hmac(key, msg)
    assert verify_hmac(key, msg, tag) is True


# tipos invalidos en compute_hmac
def test_hmac_invalid_key_type_raises():
    with pytest.raises(Exception):
        compute_hmac("not-bytes", b"m")    # key str

def test_hmac_invalid_message_type_raises():
    with pytest.raises(Exception):
        compute_hmac(b"k"*32, "not-bytes") # msg str


# tipo invalido en verify_hmac
def test_hmac_invalid_tag_type_returns_false():
    key = generate_hmac_key(256)
    msg = b"m"
    tag_ok = compute_hmac(key, msg)
    # sanity check
    assert verify_hmac(key, msg, tag_ok) is True
    # tag no-bytes --> verify_hmac captura la excepcion y devuelve False
    assert verify_hmac(key, msg, "not-bytes") is False


# clave minima: respeta HMAC_KEY_MIN_BITS
def test_generate_hmac_key_enforces_min_bits():
    import src.config as config
    min_bits = config.HMAC_KEY_MIN_BITS
    # valido: exactamente el minimo
    k = generate_hmac_key(min_bits)
    assert len(k) * 8 == min_bits
    # invalido: por debajo del minimo
    if min_bits >= 16:
        with pytest.raises(Exception):
            generate_hmac_key(min_bits - 8)


# KATs (vectores conocidos RFC 4231) para HMAC-SHA256
# RFC 4231 --> caso 1
def test_hmac_kat_rfc4231_case1():
    key = bytes([0x0b])*20
    msg = b"Hi There"
    expected_hex = ("b0344c61d8db38535ca8afceaf0bf12b"
                    "881dc200c9833da726e9376c2e32cff7")
    tag = compute_hmac(key, msg)
    assert tag.hex() == expected_hex

# RFC 4231 --> caso 2
def test_hmac_kat_rfc4231_case2():
    key = b"Jefe"
    msg = b"what do ya want for nothing?"
    expected_hex = ("5bdcc146bf60754e6a042426089575c7"
                    "5a003f089d2739839dec58b964ec3843")
    tag = compute_hmac(key, msg)
    assert tag.hex() == expected_hex


# generacion de clave: aleatoriedad basica y tamaño
def test_generate_hmac_key_random_and_size():
    k1 = generate_hmac_key(256)
    k2 = generate_hmac_key(256)
    assert len(k1) == 32 and len(k2) == 32
    assert k1 != k2  # muy improbable que coincidan


# tag truncado/extendido no debe verificar
def test_hmac_truncated_or_padded_tag_fails():
    key = generate_hmac_key(256)
    msg = b"data"
    tag = compute_hmac(key, msg)
    assert verify_hmac(key, msg, tag[:-1]) is False
    assert verify_hmac(key, msg, tag + b"\x00") is False
