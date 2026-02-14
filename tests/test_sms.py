import code
import pytest
import importlib
from queue import Queue

# modulo bajo prueba
import src.auth.short_message_service as sms_service

@pytest.fixture(autouse=True)
def reset_sms_globals():
    """
    Asegura que el estado global (CACHE y QUEUE) se reinicie
    antes de cada prueba para evitar interferencias.
    """
    # Recargar el módulo resetea sus variables globales
    importlib.reload(sms_service)
    # Nos aseguramos de que la cola esté vacía por defecto
    sms_service.set_otp_queue(None)
    yield
    # Limpieza post-prueba
    sms_service._OTP_CACHE.clear()
    sms_service.set_otp_queue(None)

# prueba que la cola global se puede configurar correctamente
def test_set_otp_queue():
    assert sms_service.OTP_QUEUE is None
    q = Queue()
    sms_service.set_otp_queue(q)
    assert sms_service.OTP_QUEUE is q

# verifica que send_otp genera un código, lo guarda en caché y lo loguea
def test_send_otp_populates_cache_and_logs(caplog):
    assert "alice" not in sms_service._OTP_CACHE
    
    with caplog.at_level("INFO"):
        sms_service.send_otp("alice", phone_masked="XXX-999")
    
    # Verificar caché
    assert "alice" in sms_service._OTP_CACHE
    entry = sms_service._OTP_CACHE["alice"]
    assert isinstance(entry, dict)
    code = entry["code"]
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()

    # Verificar log (ajustar según el formato actual, ya no se muestra el OTP)
    assert "user=alice, phone=XXX-999" in caplog.text

# prueba que el código OTP se formatea a 6 (incluyendo padding, que es necesario en este caso)
def test_send_otp_padding(monkeypatch):
    # Forzamos que random.randint devuelva 123
    monkeypatch.setattr(sms_service.random, "randint", lambda a, b: 123)
    sms_service.send_otp("bob")
    assert sms_service._OTP_CACHE["bob"]["code"] == "000123"

# prueba que el mensaje se encola
def test_send_otp_puts_message_in_queue(monkeypatch):

    # configura la cola
    q = Queue()
    sms_service.set_otp_queue(q)
    
    # codigo conocido para verificar el mensaje
    monkeypatch.setattr(sms_service.random, "randint", lambda a, b: 987654)
    
    sms_service.send_otp("charlie")
    
    assert not q.empty()
    message = q.get()
    assert message == "Tu código de verificación es 987654"
    assert q.empty()

# prueba de no error si la cola es None (estado por defecto)
def test_send_otp_does_not_fail_if_queue_is_none():
    assert sms_service.OTP_QUEUE is None
    try:
        sms_service.send_otp("dave")
    except Exception as e:
        pytest.fail(f"send_otp falló con cola Nula: {e}")

# verificacion exitosa y elimina el codigo de cache
def test_verify_otp_success_and_pops_code():
    sms_service.send_otp("eve")
    code = sms_service._OTP_CACHE["eve"]["code"]
    
    # Verificación exitosa
    assert sms_service.verify_otp("eve", code) is True
    
    # El código debe haber sido eliminado del caché
    assert "eve" not in sms_service._OTP_CACHE

# prueba de verificacion fallida (codigo incorrecto)
def test_verify_otp_failure_wrong_code():
    """verificacion fallida (codigo incorrecto) no elimina el codigo."""
    sms_service.send_otp("frank")
    
    assert sms_service.verify_otp("frank", "000000") is False
    
    # El codigo debe seguir en el cache para futuros intentos
    assert "frank" in sms_service._OTP_CACHE

# usuario no tiene verificacion pendiente
def test_verify_otp_failure_unknown_user():
    assert sms_service.verify_otp("ghost", "123456") is False

# prueba que un codigo no puede ser reutilizado (ataque de repeticion)
def test_verify_otp_failure_code_reuse():
    sms_service.send_otp("grace")
    code = sms_service._OTP_CACHE["grace"]["code"]

    assert sms_service.verify_otp("grace", code) is True  # Primer uso (exito)
    assert "grace" not in sms_service._OTP_CACHE         # Se elimina
    assert sms_service.verify_otp("grace", code) is False # Segundo uso (falla)