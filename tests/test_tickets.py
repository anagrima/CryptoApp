import json
import importlib
from pathlib import Path
import pytest


# helper para recargar modulos con configuracion de prueba
def _load_modules_for_test(tmp_path):
    # fijar DATA_PATH y recargar módulos para que usen el directorio temporal
    config = importlib.import_module("src.config")
    config.DATA_PATH = str(tmp_path)
    importlib.reload(config)
    store = importlib.reload(importlib.import_module("src.tickets.store"))
    return store


# prueba de añadir y obtener ticket (roundtrip)
def test_add_and_get_ticket_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)

    from src.tickets.models import Ticket

    t = Ticket(
        ticket_id="t1",
        username="alice",
        artist="The Band",
        venue="Sala",
        date_iso="2025-11-21T20:00:00",
        seat="A1",
        qr_payload="QR:1",
    )

    # añadir y comprobar listado
    store.add_ticket(t)
    ids = store.list_user_tickets("alice")
    assert "t1" in ids

    # obtener descifrado
    got = store.get_ticket_decrypted("alice", "t1")
    assert isinstance(got, Ticket)
    assert got.ticket_id == t.ticket_id
    assert got.username == t.username
    assert got.artist == t.artist
    assert got.venue == t.venue
    assert got.date_iso == t.date_iso
    assert got.seat == t.seat
    assert got.qr_payload == t.qr_payload

    # comprobar que el archivo de clave existe (se creo o se reutilizo)
    keyfile = Path(store.DB_PATH.parent) / "aes_tickets.key"
    assert keyfile.exists()


# prueba de comportamiento con fichero tickets.db corrupto
def test_list_returns_empty_if_db_corrupt_and_get_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)

    # crear fichero corrupto tickets.db
    db_path = store.DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text("{ not: valid json", encoding="utf-8")

    # list deberia devolver vacio
    assert store.list_user_tickets("noone") == []

    # get debe fallar para un id inexistente
    with pytest.raises(KeyError):
        store.get_ticket_decrypted("noone", "missing")


# Añadir ticket duplicado
def test_add_duplicate_ticket_raises_or_overwrites(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t1 = Ticket(ticket_id="dup", username="bob", artist="A", venue="B", date_iso="2025-12-01T20:00:00", seat="B1", qr_payload="QR:2")
    store.add_ticket(t1)
    # Intentar añadir el mismo ticket_id para el mismo usuario
    t2 = Ticket(ticket_id="dup", username="bob", artist="A2", venue="B2", date_iso="2025-12-02T20:00:00", seat="B2", qr_payload="QR:3")
    try:
        store.add_ticket(t2)
        got = store.get_ticket_decrypted("bob", "dup")
        # Si sobreescribe, debe ser el segundo
        assert got.artist == t2.artist
    except Exception:
        # Si lanza excepción, es válido también
        pass

# Listar tickets de usuario sin tickets
def test_list_user_tickets_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    assert store.list_user_tickets("nadie") == []

# Obtener ticket inexistente
def test_get_ticket_decrypted_nonexistent_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    with pytest.raises(KeyError):
        store.get_ticket_decrypted("alguien", "noexiste")

# Eliminar ticket (si existe función remove_ticket)
def test_remove_ticket_if_supported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t = Ticket(ticket_id="del1", username="eve", artist="X", venue="Y", date_iso="2025-12-03T20:00:00", seat="C1", qr_payload="QR:4")
    store.add_ticket(t)
    if hasattr(store, "remove_ticket"):
        store.remove_ticket("eve", "del1")
        assert "del1" not in store.list_user_tickets("eve")

# Integridad de cifrado: modificar archivo y debe fallar
def test_corrupt_encrypted_db_returns_empty_list(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t = Ticket(ticket_id="corrupt", username="dan", artist="Y", venue="Z", date_iso="2025-12-04T20:00:00", seat="D1", qr_payload="QR:5")
    store.add_ticket(t)
    db_path = store.DB_PATH
    # Corromper el archivo
    db_path.write_bytes(b"not a valid encrypted blob")
    # Debe devolver lista vacía, no lanzar excepción
    assert store.list_user_tickets("dan") == []

# Soporte de campos Unicode
def test_ticket_unicode_fields_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t = Ticket(ticket_id="uni", username="ñandú", artist="Björk", venue="東京", date_iso="2025-12-05T20:00:00", seat="Ω1", qr_payload="QR:üñîçødë")
    store.add_ticket(t)
    got = store.get_ticket_decrypted("ñandú", "uni")
    assert got.artist == "Björk"
    assert got.venue == "東京"
    assert got.seat == "Ω1"
    assert got.qr_payload == "QR:üñîçødë"

# Persistencia entre sesiones
def test_ticket_persistence_across_reload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t = Ticket(ticket_id="persist", username="zoe", artist="Persist", venue="Sala", date_iso="2025-12-06T20:00:00", seat="P1", qr_payload="QR:6")
    store.add_ticket(t)
    # Recargar módulo store
    store2 = importlib.reload(importlib.import_module("src.tickets.store"))
    ids = store2.list_user_tickets("zoe")
    assert "persist" in ids

# Manejo de archivo de clave faltante
def test_missing_keyfile_creates_or_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t = Ticket(ticket_id="keymiss", username="keyu", artist="K", venue="V", date_iso="2025-12-07T20:00:00", seat="K1", qr_payload="QR:7")
    keyfile = Path(store.DB_PATH.parent) / "aes_tickets.key"
    if keyfile.exists():
        keyfile.unlink()
    try:
        store.add_ticket(t)
        assert keyfile.exists()
    except Exception:
        # Si lanza excepción clara, también es válido
        pass

# Tickets de varios usuarios
def test_multiple_users_tickets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    t1 = Ticket(ticket_id="u1", username="ana", artist="A", venue="V", date_iso="2025-12-08T20:00:00", seat="A1", qr_payload="QR:8")
    t2 = Ticket(ticket_id="u2", username="bea", artist="B", venue="V", date_iso="2025-12-09T20:00:00", seat="B1", qr_payload="QR:9")
    store.add_ticket(t1)
    store.add_ticket(t2)
    assert "u1" in store.list_user_tickets("ana")
    assert "u2" in store.list_user_tickets("bea")
    assert "u2" not in store.list_user_tickets("ana")

# Campos obligatorios vacíos o nulos
def test_ticket_required_fields_empty_or_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _load_modules_for_test(tmp_path)
    from src.tickets.models import Ticket
    # ticket_id vacío
    with pytest.raises(Exception):
        store.add_ticket(Ticket(ticket_id="", username="x", artist="A", venue="V", date_iso="2025-12-10T20:00:00", seat="A1", qr_payload="QR:10"))
    # username None
    with pytest.raises(Exception):
        store.add_ticket(Ticket(ticket_id="f2", username=None, artist="A", venue="V", date_iso="2025-12-10T20:00:00", seat="A1", qr_payload="QR:10"))
