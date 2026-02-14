# mfa_service
import random
from ..logger import logger

_OTP_CACHE = {}  # {username: code}
OTP_QUEUE = None # la cola para comunicarse con la GUI

# configurar la cola de comunicacion
def set_otp_queue(q: object):
    # permite que el lanzador principal configure la cola de comunicación
    global OTP_QUEUE
    OTP_QUEUE = q

# enviar el codigo OTP al usuario (simulado)
def send_otp(username: str, phone_masked: str = "XXX-XXX-123"):
    # codigo aleatorio de 6 digitos
    code = f"{random.randint(0, 999999):06d}"
    # almacenar el codigo junto con el contador de intentos
    _OTP_CACHE[username] = {'code': code, 'attempts': 0}

    # no registrar el codigo en logs
    logger.info(f"SMS 2FA: user={username}, phone={phone_masked}, OTP enviado (NO logueado).")
    if OTP_QUEUE:
        # mensaje que se inserta en la cola y se muestra en la app de SMS
        message = f"Tu código de verificación es {code}"
        OTP_QUEUE.put(message)


# verificar el codigo OTP proporcionado por el usuario
def verify_otp(username: str, code: str) -> bool:

    # se toma el codigo que hay en la cola para el usuario
    entry = _OTP_CACHE.get(username)
    if not entry:
        logger.debug(f"OTP: No hay código para {username} (posiblemente expirado o nunca enviado)")
        return False
    
    # comprueba que el codigo proporcionado coincide con el almacenado
    ok = entry['code'] == code
    if ok:
        _OTP_CACHE.pop(username, None)
        logger.info(f"OTP correcto para {username}")
        return True
    else:
        # registrar el intento fallido
        entry['attempts'] += 1
        logger.info(f"Intento fallido de OTP para {username}. Intentos registrados: {entry['attempts']}")
        return False