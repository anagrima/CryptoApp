# tests/test_hybrid.py
import pytest
import json
import os

# Módulos del proyecto
from src.crypto import hybrid
from src.crypto import asymmetric

# Fixture para generar un par de claves RSA para las pruebas
@pytest.fixture(scope="module")
def rsa_key_pair():
    """
    Genera un par de claves RSA una vez por módulo.
    Usamos 2048 bits como en asymmetric.py
    """
    priv_key, pub_key = asymmetric.generate_key_pair(2048)
    return priv_key, pub_key

# Pruebas de cifrado y descifrado híbrido, ciclo completo
def test_hybrid_roundtrip_basic(rsa_key_pair, caplog):
    priv_key, pub_key = rsa_key_pair
    data = b"Este es un mensaje secreto de prueba"
    
    with caplog.at_level("INFO"):
        encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data)
    assert "SERVIDOR: Cifrado híbrido completado" in caplog.text
    
    caplog.clear()
    with caplog.at_level("INFO"):
        decrypted_data = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert "CLIENTE: Descifrado híbrido completado" in caplog.text

    assert decrypted_data == data

# Prueba con AAD del ciclo completo
def test_hybrid_roundtrip_with_aad(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    data = b"Datos principales del ticket"
    aad = b"metadata_del_usuario:alice"
    
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data, aad=aad)
    decrypted_data = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    
    assert decrypted_data == data

# Prueba con diferentes tamaños de datos, incluyendo datos vacíos
@pytest.mark.parametrize("data_size", [0, 1, 1024, 5 * 1024])
def test_hybrid_roundtrip_various_sizes(rsa_key_pair, data_size):
    priv_key, pub_key = rsa_key_pair
    data = os.urandom(data_size)
    aad = b"id:12345"
    
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data, aad=aad)
    decrypted_data = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    
    assert decrypted_data == data

# Pruebas de fallo en descifrado con clave privada incorrecta
def test_decrypt_fails_with_wrong_private_key(rsa_key_pair):
    _ , pub_key_1 = rsa_key_pair
    
    # Generamos un par de claves completamente diferente
    priv_key_2, _ = asymmetric.generate_key_pair(2048)
    
    data = b"mensaje para clave 1"
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key_1, data)
    
    # Intentar descifrar con priv_key_2 debe fallar
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key_2, encrypted_bundle)

# Prueba con JSON corrupto (bundle esta corrupto    )
def test_decrypt_fails_with_corrupt_json(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bad_bundle = b'{"iv": "123", "ciphertext": "abc"' # JSON mal formado
    
    with pytest.raises(json.JSONDecodeError):
        hybrid.decrypt_hybrid_bundle(priv_key, bad_bundle)

# Prueba con campos faltantes en el bundle
@pytest.mark.parametrize("missing_key", ["encrypted_aes_key", "iv", "ciphertext", "aad"])
def test_decrypt_fails_with_missing_key_in_bundle(rsa_key_pair, missing_key):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    
    bundle_dict = json.loads(encrypted_bundle.decode('utf-8'))
    bundle_dict.pop(missing_key) # Eliminar una clave esencial
    bad_bundle_bytes = json.dumps(bundle_dict).encode('utf-8')
    
    with pytest.raises(KeyError):
        hybrid.decrypt_hybrid_bundle(priv_key, bad_bundle_bytes)

# Prueba con valores hexadecimales invalidos
def test_decrypt_fails_with_bad_hex_value(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    
    bundle_dict = json.loads(encrypted_bundle.decode('utf-8'))
    bundle_dict["iv"] = "esto-no-es-hex-Z" # 'Z' no es un carácter hexadecimal
    bad_bundle_bytes = json.dumps(bundle_dict).encode('utf-8')
    
    with pytest.raises(ValueError): # bytes.fromhex() lanza ValueError
        hybrid.decrypt_hybrid_bundle(priv_key, bad_bundle_bytes)

# Prueba con ciphertext manipulado
def test_decrypt_fails_with_tampered_ciphertext(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle_bytes = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    
    bundle_dict = json.loads(encrypted_bundle_bytes.decode('utf-8'))
    
    # Manipulamos el ciphertext (cambiamos el primer carácter)
    ct_hex = bundle_dict["ciphertext"]
    tampered_ct_hex = "0" + ct_hex[1:] if ct_hex[0] != "0" else "1" + ct_hex[1:]
    bundle_dict["ciphertext"] = tampered_ct_hex
    
    tampered_bundle_bytes = json.dumps(bundle_dict).encode('utf-8')
    
    # AES-GCM debe fallar la verificación de integridad (AuthenticationTag)
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, tampered_bundle_bytes)

# Prueba con AAD manipulado
def test_decrypt_fails_with_tampered_aad(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle_bytes = hybrid.encrypt_hybrid_bundle(pub_key, b"data", aad=b"A")
    
    bundle_dict = json.loads(encrypted_bundle_bytes.decode('utf-8'))
    
    # Manipulamos el AAD (que está en el 'bundle')
    bundle_dict["aad"] = b"B".hex() # El original era b"A".hex()
    
    tampered_bundle_bytes = json.dumps(bundle_dict).encode('utf-8')
    
    # AES-GCM debe fallar la verificación
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, tampered_bundle_bytes)

# Prueba con datos grandes (>2MB)
def test_hybrid_large_data(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    data = os.urandom(2 * 1024 * 1024)
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data)
    decrypted = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert decrypted == data

# Pruebas con AAD
@pytest.mark.parametrize("aad", [b"", None])
def test_hybrid_with_empty_and_none_aad(rsa_key_pair, aad):
    """Cifrado/descifrado con AAD vacío y None."""
    priv_key, pub_key = rsa_key_pair
    data = b"test"
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data, aad=aad)
    decrypted = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert decrypted == data

# Pruebas con campos adicionales
def test_hybrid_bundle_with_extra_fields(rsa_key_pair):
    """El descifrado ignora campos extra en el bundle."""
    priv_key, pub_key = rsa_key_pair
    data = b"bundle extra"
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data)
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle["extra"] = "valor"
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    assert hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes) == data

# Prueba con tipos incorrectos en campos clave
def test_hybrid_bundle_with_wrong_types(rsa_key_pair):
    """Bundle con tipos incorrectos en campos clave."""
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle["iv"] = 12345  # Debe ser string
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Prueba con AAD incorrecto
def test_hybrid_decrypt_with_wrong_aad(rsa_key_pair):
    """Descifrado con AAD incorrecto debe fallar."""
    priv_key, pub_key = rsa_key_pair
    data = b"AAD test"
    aad = b"A"
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data, aad=aad)
    # Manipular el bundle para cambiar el AAD
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle["aad"] = b"B".hex()
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Prueba con clave RSA grande
def test_hybrid_with_large_rsa_key():
    """clave RSA de 4096 bits."""
    priv_key, pub_key = asymmetric.generate_key_pair(4096)
    data = b"RSA 4096 test"
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data)
    decrypted = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert decrypted == data

# Prueba con datos no UTF-8
def test_hybrid_bundle_with_non_utf8_bytes(rsa_key_pair):
    """Descifrado de bundle con bytes no UTF-8 debe fallar."""
    priv_key, pub_key = rsa_key_pair
    bad_bytes = b'\xff\xfe\xfd\xfc\xfb\xfa'
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bad_bytes)

# Prueba con todos los campos vacios
def test_hybrid_bundle_all_fields_empty(rsa_key_pair):
    """Bundle con todos los campos vacíos debe fallar."""
    priv_key, _ = rsa_key_pair
    bundle = {"encrypted_aes_key": "", "iv": "", "ciphertext": "", "aad": ""}
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Prueba con clave simetrica cifrada invalida
def test_hybrid_bundle_with_invalid_encrypted_aes_key(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle["encrypted_aes_key"] = "00ffzz"  # No es hex válido ni un bloque RSA válido
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# --- TESTS PARA SUBIR COBERTURA ---
@pytest.mark.parametrize("data", [b"a", b"ab", b"abc", b"\x00", b"\xff", bytes(range(256)), b"\x00"*32, b"\xff"*32])
def test_hybrid_various_small_and_edge_data(rsa_key_pair, data):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data)
    decrypted = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert decrypted == data

# AAD muy largo
def test_hybrid_with_long_aad(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    data = b"payload"
    aad = os.urandom(10*1024)  # 10 KB de AAD
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, data, aad=aad)
    decrypted = hybrid.decrypt_hybrid_bundle(priv_key, encrypted_bundle)
    assert decrypted == data

# Bundle con campo 'aad' ausente
def test_hybrid_bundle_missing_aad_field(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data")
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle.pop("aad")
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(KeyError):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con campo 'aad' no hexadecimal
def test_hybrid_bundle_aad_not_hex(rsa_key_pair):
    priv_key, pub_key = rsa_key_pair
    encrypted_bundle = hybrid.encrypt_hybrid_bundle(pub_key, b"data", aad=b"A")
    bundle = json.loads(encrypted_bundle.decode("utf-8"))
    bundle["aad"] = "no-es-hex"
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con JSON completamente vacío

def test_hybrid_bundle_empty_json(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bundle_bytes = b"{}"
    with pytest.raises(KeyError):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con JSON que es un string en vez de un dict

def test_hybrid_bundle_json_string_instead_of_dict(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bundle_bytes = b'"no es un dict"'
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con campos válidos pero con espacios en blanco

def test_hybrid_bundle_fields_with_spaces(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bundle = {"encrypted_aes_key": "   ", "iv": "   ", "ciphertext": "   ", "aad": "   "}
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con campos válidos pero con valores null

def test_hybrid_bundle_fields_null(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bundle = {"encrypted_aes_key": None, "iv": None, "ciphertext": None, "aad": None}
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)

# Bundle con campos válidos pero con listas en vez de strings

def test_hybrid_bundle_fields_as_lists(rsa_key_pair):
    priv_key, _ = rsa_key_pair
    bundle = {"encrypted_aes_key": [1,2,3], "iv": [4,5,6], "ciphertext": [7,8,9], "aad": [10,11,12]}
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    with pytest.raises(Exception):
        hybrid.decrypt_hybrid_bundle(priv_key, bundle_bytes)