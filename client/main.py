import sys
import os
import threading
import queue

# Configura el path de Python para que encuentre la carpeta 'src'
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Importa las aplicaciones despues de configurar el path para evitar errores de importacion
from client.client_app import run as run_main_app
from client.sms_app import start_sms_app

from src.pki.pki_init import initialize_pki
from src.sign.sign_service import set_issuer_password


if __name__ == "__main__":
    """ ORQUESTACION DE LOS HILOS DE EJECUCION PARA CADA APP"""

    # crea la cola para los OTP (del short message service)
    otp_queue = queue.Queue()

    # inicializa la PKI (crea las ACs si no existen)
    print("Inicializando la infraestructura de clave pública (PKI)...")

    # si existen los certificados de las ACs, no hace falta inicializar la PKI de nuevo
    # asi se pueden mantener los certificados ya creados entre distintas ejecuciones del programa
    if not os.path.exists("data/keystore/root_ca_cert.pem") or not os.path.exists("data/keystore/subordinate_ca_cert.pem"):
        print("Configurando la PKI por primera vez...")
        initialize_pki()

    # crea e inicia un hilo para cada ventana: interfaz principal de cliente y app de SMS
    main_app_thread = threading.Thread(target=run_main_app, args=(otp_queue,))
    sms_app_thread = threading.Thread(target=start_sms_app, args=(otp_queue,))

    print("Lanzando aplicación principal y app de SMS...")
    main_app_thread.start()
    sms_app_thread.start()

    main_app_thread.join()
    sms_app_thread.join()