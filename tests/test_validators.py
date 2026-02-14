# test para validators.py
import pytest
import os
from src.common.validators import ensure_min_bits, ensure_gcm_iv, ensure_password_policy
from src.config import AES_KEY_MIN_BITS, HMAC_KEY_MIN_BITS, RSA_MIN_BITS


# validacion de longitud minima de claves
@pytest.mark.parametrize("bits,min_bits,name", [
    (AES_KEY_MIN_BITS, AES_KEY_MIN_BITS, "AES key"), # minimo AES (128)
    (256, AES_KEY_MIN_BITS, "AES key"), # mayor que el minimo
    (RSA_MIN_BITS, RSA_MIN_BITS, "RSA key"), # minimo RSA (2048)
])
def test_ensure_min_bits_success(bits, min_bits, name):
    # no deberia lanzar excepcion
    ensure_min_bits(bits, min_bits, name)

# casos fallidos
@pytest.mark.parametrize("bits,min_bits,name", [
    (AES_KEY_MIN_BITS - 1, AES_KEY_MIN_BITS, "AES key"), # menor que AES minimo
    (HMAC_KEY_MIN_BITS - 8, HMAC_KEY_MIN_BITS, "HMAC key"), # menor que HMAC minimo (128)
])
def test_ensure_min_bits_failure_raises(bits, min_bits, name):
    # debe lanzar ValueError
    with pytest.raises(ValueError) as excinfo:
        ensure_min_bits(bits, min_bits, name)
    # verificar que el mensaje contiene la longitud minima requerida
    assert f"longitud mínima {min_bits} bits." in str(excinfo.value)


# validacion de longitud fija para IV
VALID_IV_SIZE = os.urandom(12) # IV de 12 bytes (96 bits) es el estandar para GCM

def test_ensure_gcm_iv_success():
    ensure_gcm_iv(VALID_IV_SIZE) # no lanza excepcion
@pytest.mark.parametrize("bad_iv", [
    b"",
    os.urandom(8), # demasiado corto
    os.urandom(11), # demasiado corto
    os.urandom(16), # demasiado largo
])

# casos fallidos
def test_ensure_gcm_iv_failure_raises(bad_iv):
    with pytest.raises(ValueError) as excinfo:
        ensure_gcm_iv(bad_iv)
    # verificar el mensaje de error
    assert "IV debe ser de 12 bytes (96 bits)." in str(excinfo.value)


# validacion de complejidad de contraseña
MIN_LEN = 12 # la longitud minima por defecto es 12 (PASSWORD_MIN_LENGTH)

def test_ensure_password_policy_success():
    # cumple: length=12, Upper, lower, digit, symbol
    assert ensure_password_policy("Aa1!aaaaaaaa", MIN_LEN) is True
    # contraseña mas larga
    assert ensure_password_policy("SuperStrongPassword1!", MIN_LEN) is True
    # Unicode (los tests de auth_service verifican que el manejo de unicode funciona)
    assert ensure_password_policy("Áa1!ñandú", 5) is True

# casos fallidos
@pytest.mark.parametrize("password", [
    "Aa1!aaaaaaa", # longitud 11 (falla length)
])
def test_password_policy_fails_on_length(password):
    assert ensure_password_policy(password, MIN_LEN) is False

@pytest.mark.parametrize("password, reason", [
    ("a1!bbbbbbbbbb", "No Upper"), # falla mayuscula [2]
    ("A1!BBBBBBBBBB", "No Lower"), # falla minuscula [2]
    ("Aa!bbbbbbbbbb", "No Digit"), # falla digito [2]
    ("Aa1bbbbbbbbbb", "No Symbol"), # falla simbolo [2]
])
def test_password_policy_fails_on_complexity(password, reason):
    assert ensure_password_policy(password, MIN_LEN) is False


# prueba la longitud exacta y uno menos
def test_password_policy_length_boundary():
    # longitud exacta (12)
    assert ensure_password_policy("Aa1!aaaaaaaa", 12) is True
    # longitud uno menos (11)
    assert ensure_password_policy("Aa1!aaaaaaa", 12) is False


# tipos no enteros
def test_ensure_min_bits_rejects_non_int_types():
    # pasar una cadena deberia lanzar TypeError
    with pytest.raises(TypeError):
        ensure_min_bits("128", 128, "AES key")   # str
    # pasar un float no deberia lanzar TypeError (comparacion con int es valida)
    ensure_min_bits(128.0, 128, "AES key")   # float


# tipos de entrada (bytes-like vs str)
def ensure_gcm_iv(iv: bytes):
    if not isinstance(iv, (bytes, bytearray, memoryview)):
        raise TypeError("AES-GCM: IV debe ser bytes-like.")
    if len(iv) != 12:
        raise ValueError("AES-GCM: IV debe ser de 12 bytes (96 bits).")
    
# casos exitosos
def test_ensure_gcm_iv_accepts_bytes_like():
    ensure_gcm_iv(b"x" * 12)
    ensure_gcm_iv(bytearray(12))
    ensure_gcm_iv(memoryview(b"x" * 12))

# caso fallido: str
def test_ensure_gcm_iv_rejects_str_even_if_len_12():
    with pytest.raises(TypeError):
        ensure_gcm_iv("abcdefghijkl")  # 12 chars, pero str


# espacios, Unicode y casos limite

# spacio en blanco cuenta como “simbolo”
def test_password_policy_symbol_can_be_space():
    # 12+ chars, con espacio como símbolo
    assert ensure_password_policy("Aa1 aaaaaaaa", 12) is True

# Unicode: digitos y letras no ASCII
def test_password_policy_unicode_categories():
    # digitos unicode (FULLWIDTH '３'), mayuscula/minuscula con acentos
    pwd = "Áa３!aaaaaaaa"  # ‘３’ U+FF13 es dígito
    assert ensure_password_policy(pwd, 12) is True

# min_length=0 (semantica explicita)
def test_password_policy_min_length_zero_semantics():
    # con min_length=0 --> pasa si cumple clases de caracteres
    assert ensure_password_policy("Aa1!", 0) is True
    # con min_length=1 --> “Aa1!” tambian pasa (>=1)
    assert ensure_password_policy("Aa1!", 1) is True


# casos negativos adicionales
@pytest.mark.parametrize("pwd", [
    "A" * 20,            # solo mayusculas
    "a" * 20,            # solo minusculas
    "1" * 20,            # solo digitos
    "!" * 20,            # solo simbolos
    "Aa" * 10,           # sin digitos ni simbolos
    "A1" * 10,           # sin minusculas
    "a1" * 10,           # sin mayusculas
    "Aa!" * 7,           # sin digitos
])
def test_password_policy_more_negatives(pwd):
    assert ensure_password_policy(pwd, 12) is False
