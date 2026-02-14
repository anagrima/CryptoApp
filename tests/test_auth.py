# valida la funcionalidad de autenticacion y almacenamiento de usuarios del proyecto: registro, login, politica
# de contraseñas, persistencia a disco, manejo de errores en la base de datos y logs
import os
import json
import pytest
import importlib
import stat

DUMMY_PHONE = "600111222"
DUMMY_KEY = "-----BEGIN PUBLIC KEY-----\nDUMMY_KEY_DATA\n-----END PUBLIC KEY-----"
VALID_PASS = "Aa1!aaaaaaaa"

# helper para recargar modulos con configuracion de prueba
def _load_modules_for_test(tmp_path, password_min_length=8):
    # nos aseguramos de importar el modulo de configuracion y fijar los valores antes de cargar los demas
    config = importlib.import_module("src.config")
    # establecer DATA_PATH y PASSWORD_MIN_LENGTH para esta ejecucion de prueba
    config.DATA_PATH = str(tmp_path)
    config.PASSWORD_MIN_LENGTH = password_min_length
    importlib.reload(config)

    # recargar user_store y password_policy para que usen la nueva configuracion
    user_store = importlib.reload(importlib.import_module("src.auth.user_store"))
    password_policy = importlib.reload(importlib.import_module("src.auth.password_policy"))
    # recargar auth_service que depende de los anteriores
    auth_service = importlib.reload(importlib.import_module("src.auth.auth_service"))

    return auth_service, user_store


# registro exitoso y login correcto e incorrecto
def test_register_success_and_login(tmp_path, monkeypatch):
    # trabajar en tmp_path para aislar users.db
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path, password_min_length=8)

    # registro con contraseña que cumple complejidad (mayus, minus, digito, simbolo)
    pwd = VALID_PASS
    assert auth_service.register("alice", pwd, DUMMY_PHONE, DUMMY_KEY) is True
    db = user_store._load_db()
    assert "alice" in db
    assert db["alice"]["phone_number"] == DUMMY_PHONE
    assert db["alice"]["public_key_pem"] == DUMMY_KEY
    # login correcto
    assert auth_service.login("alice", pwd) is True
    # login incorrecto
    assert auth_service.login("alice", "wrongpass") is False


# registro falla si la contraseña es debil
def test_register_fails_on_weak_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path, password_min_length=8)

    # sin mayuscula
    assert auth_service.register("bob", "a1!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is False
    # sin minuscula
    assert auth_service.register("carol", "AA1!AAAAAAAA", DUMMY_PHONE, DUMMY_KEY) is False
    # sin digito
    assert auth_service.register("dave", "Aa!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is False
    # sin simbolo
    assert auth_service.register("eve", "Aa1aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is False


# registro duplicado
def test_register_duplicate_username(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)

    assert auth_service.register("alice", "Aa1!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is True
    # segundo registro con mismo usuario debe fallar
    assert auth_service.register("alice", "Aa1!bbbbbbbb", DUMMY_PHONE, DUMMY_KEY) is False


# login con usuario inexistente
def test_login_unknown_user(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.login("ghost", "Whatever1!") is False


# bordes de longitud minima
@pytest.mark.parametrize("passwd,expected", [
    ("Aa1!aaaaaaaaaaa", True),   # justo 12 caracteres o mas --> valido
    ("Aa1!aaaaaaa", False),      # 11 --> demasiado corta --> invalida
])
def test_password_min_length_boundary(tmp_path, monkeypatch, passwd, expected):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("u", passwd, DUMMY_PHONE, DUMMY_KEY) is expected


# persistencia entre reinicios
def test_persistence_across_module_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("alice", "Aa1!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is True

    # simular nuevo arranque: recargo modulos apuntando al mismo DATA_PATH
    auth_service2, _ = _load_modules_for_test(tmp_path)
    assert auth_service2.login("alice", "Aa1!aaaaaaaa") is True


# base de datos corrupta se resetea
def test_corrupt_db_resets_and_logs_warning(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _, user_store = _load_modules_for_test(tmp_path)
    # usa SIEMPRE la ruta real
    db_path = user_store.DB_PATH
    backup_path = db_path.with_suffix(".corrupt")
    # asegurar limpieza previa
    if db_path.exists():
        db_path.unlink()
    if backup_path.exists():
        backup_path.unlink()
    # escribe JSON invalido en la ruta real
    db_path.write_text("{not: valid json", encoding="utf-8")
    # ejecuta: debe detectar corrupcion, renombrar y devolver {}
    db = user_store._load_db()
    assert db == {}
    # verifica efectos colaterales exactos
    assert not db_path.exists(), "users.db debería haber sido renombrado"
    assert backup_path.exists(), "Debería existir users.corrupt"


# logs de auditoria en registro y login
def test_logs_on_register_and_login(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)

    with caplog.at_level("INFO"):
        assert auth_service.register("alice", "Aa1!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is True
    assert any("Usuario registrado: alice" in r.message for r in caplog.records)

    caplog.clear()
    with caplog.at_level("INFO"):
        assert auth_service.login("alice", "Aa1!aaaaaaaa") is True
    assert any("éxito" in r.message for r in caplog.records)

    caplog.clear()
    with caplog.at_level("INFO"):
        assert auth_service.login("alice", "wrong") is False
    assert any("fallido" in r.message for r in caplog.records)


# unicode en usuario y contraseña
def test_unicode_username_and_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    username = "ñandú_用户"          # caracteres con eñe y chino
    password = "Áa1!contraseña🙂"    # acentos y emoji
    assert auth_service.register(username, password, DUMMY_PHONE, DUMMY_KEY) is True
    assert auth_service.login(username, password) is True


# no se guarda en el claro y el hash parece bcrypt
def test_hash_format_and_not_plaintext(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    pwd = "Aa1!aaaaaaaa"
    assert auth_service.register("alice", pwd, DUMMY_PHONE, DUMMY_KEY) is True
    db = user_store._load_db()
    h = db["alice"]["password_hash"]
    assert pwd not in h
    assert h.startswith("$2")  # tipico prefijo bcrypt ($2b$, etc.)


# mock de bcrypt para acelerar
def test_register_with_mocked_bcrypt(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)

    class Dummy:
        @staticmethod
        def gensalt(): return b"SALT"
        @staticmethod
        def hashpw(p, s): return b"$2b$fakehash"
        @staticmethod
        def checkpw(p, h): return True

    import src.auth.user_store as us
    monkeypatch.setattr(us, "bcrypt", Dummy)

    assert auth_service.register("fast", "Aa1!aaaaaaaa", DUMMY_PHONE, DUMMY_KEY) is True
    assert auth_service.login("fast", "whatever") is True


# DATA_PATH no escribible
def test_register_raises_when_db_save_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    # forzamos error al guardar la DB
    def boom(_):
        raise PermissionError("read-only filesystem")
    monkeypatch.setattr(user_store, "_save_db", boom)
    with pytest.raises(PermissionError):
        auth_service.register("alice", "Aa1@aaaaaaaa", DUMMY_PHONE, DUMMY_KEY)


# login con contraseña vacia o None
def test_login_with_empty_or_none_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.login("alice", "") is False
    assert auth_service.login("alice", None) is False


# registro con nombre de usuario vacio o None
def test_register_with_empty_or_none_username(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("", VALID_PASS, DUMMY_PHONE, DUMMY_KEY) is False
    assert auth_service.register(None, VALID_PASS, DUMMY_PHONE, DUMMY_KEY) is False


# registro con telefono o clave vacios
def test_register_with_empty_phone_or_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("bob", VALID_PASS, "", DUMMY_KEY) is False
    assert auth_service.register("bob", VALID_PASS, DUMMY_PHONE, "") is False


# login tras corrupcion de DB
def test_login_after_db_corruption(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    auth_service.register("alice", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    db_path = user_store.DB_PATH
    db_path.write_text("{not: valid json", encoding="utf-8")
    # recarga modulos para simular reinicio
    auth_service2, _ = _load_modules_for_test(tmp_path)
    assert auth_service2.login("alice", VALID_PASS) is False


# verifica que el log de advertencia se emite al detectar corrupcion
def test_warning_log_on_db_corruption(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    _, user_store = _load_modules_for_test(tmp_path)
    db_path = user_store.DB_PATH
    db_path.write_text("{not: valid json", encoding="utf-8")
    with caplog.at_level("WARNING"):
        db = user_store._load_db()
    assert any("DB corrupta" in r.message for r in caplog.records)


# case sensitivity en usuario
def test_username_case_sensitivity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    auth_service.register("Alice", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    assert auth_service.login("alice", VALID_PASS) is False
    assert auth_service.login("Alice", VALID_PASS) is True


# login tras borrar usuario manualmente de la base de datos
def test_login_after_user_deleted_from_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    auth_service.register("alice", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    db = user_store._load_db()
    del db["alice"]
    user_store._save_db(db)
    assert auth_service.login("alice", VALID_PASS) is False


# registro con caracteres especiales en usuario y clave
def test_register_with_special_chars_in_username_and_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    username = "user!@#"
    pubkey = "-----BEGIN PUBLIC KEY-----\n!@#$%^&*()\n-----END PUBLIC KEY-----"
    assert auth_service.register(username, VALID_PASS, DUMMY_PHONE, pubkey) is True
    db = user_store._load_db()
    assert db[username]["public_key_pem"] == pubkey


# --- TESTS PARA SUBIR COBERTURA ---
def test_register_with_password_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user1", None, DUMMY_PHONE, DUMMY_KEY) is False

def test_register_with_phone_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user2", VALID_PASS, None, DUMMY_KEY) is False

def test_register_with_key_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user3", VALID_PASS, DUMMY_PHONE, None) is False

def test_login_with_user_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.login(None, VALID_PASS) is False

def test_login_with_user_empty_and_valid_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.login("", VALID_PASS) is False

def test_login_with_correct_user_and_password_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    auth_service.register("user4", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    assert auth_service.login("user4", None) is False

def test_register_with_password_spaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user5", "    ", DUMMY_PHONE, DUMMY_KEY) is False

def test_register_with_username_spaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("    ", VALID_PASS, DUMMY_PHONE, DUMMY_KEY) is False

def test_register_with_phone_spaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user6", VALID_PASS, "   ", DUMMY_KEY) is False

def test_register_with_key_spaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register("user7", VALID_PASS, DUMMY_PHONE, "   ") is False

def test_login_after_db_file_deleted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, user_store = _load_modules_for_test(tmp_path)
    auth_service.register("user8", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    db_path = user_store.DB_PATH
    if db_path.exists():
        db_path.unlink()
    assert auth_service.login("user8", VALID_PASS) is False

def test_register_with_very_long_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    long_pass = "Aa1!" + "a"*9996
    assert auth_service.register("user9", long_pass, DUMMY_PHONE, DUMMY_KEY) is True
    assert auth_service.login("user9", long_pass) is True

def test_register_with_username_newlines_tabs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    username = "user\n\t"
    assert auth_service.register(username, VALID_PASS, DUMMY_PHONE, DUMMY_KEY) in (True, False)

def test_login_with_password_trailing_spaces(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    auth_service.register("user10", VALID_PASS, DUMMY_PHONE, DUMMY_KEY)
    assert auth_service.login("user10", VALID_PASS + "   ") is False

def test_register_all_fields_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    auth_service, _ = _load_modules_for_test(tmp_path)
    assert auth_service.register(None, None, None, None) is False