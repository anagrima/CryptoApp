# configuracion del sistema de logging
import logging
from .config import LOG_FILE

logger = logging.getLogger("crypto_app") # obtenemos el logger principal
logger.setLevel(logging.DEBUG)           # establecemos el nivel de logging a DEBUG

# si el logger no tiene handlers --> se añade un FileHandler para guardar los logs en un archivo
if not logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')                        # creamos el  FileHandler
    fh.setLevel(logging.DEBUG)                                                  # establecemos el nivel de logging a DEBUG
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')  # definimos el formato
    fh.setFormatter(formatter)
    logger.addHandler(fh)                                                       # añadimos el handler al logger
