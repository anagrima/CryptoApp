import json
from .symmetric import generate_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from .asymmetric import encrypt_with_public_key, decrypt_with_private_key
from ..logger import logger

# funcion para aplicar cifrado hibrido con RSA-OAEP (asimetrico) y AES-GCM (simetrico)
def encrypt_hybrid_bundle(public_key, data: bytes, aad: bytes = b"") -> bytes:
    try:
        # genera clave AES
        aes_key = generate_aes_key(256)
        
        # cifrar con AES-GCM
        encrypted_data = encrypt_aes_gcm(aes_key, data, aad)
        
        # cifrar clave AES con RSA-OAEP para enviarla de forma segura
        encrypted_aes_key = encrypt_with_public_key(public_key, aes_key)
        
        # crear el "paquete" (bundle) para almacenar y enviar
        # .hex() para que sea compatible con JSON
        bundle = {
            "encrypted_aes_key": encrypted_aes_key.hex(),
            "iv": encrypted_data['iv'].hex(),
            "ciphertext": encrypted_data['ciphertext'].hex(),
            "aad": encrypted_data['aad'].hex() if encrypted_data.get('aad') is not None else ""
        }
        
        logger.info("SERVIDOR: Cifrado híbrido completado.")

        # devolver JSON como bytes
        return json.dumps(bundle).encode('utf-8')
        
    except Exception as e:
        logger.debug(f"SERVIDOR: Error durante el cifrado híbrido: {e}")
        raise

# funcion para aplicar descifrado hibrido con RSA-OAEP (asimetrico) y AES-GCM (simetrico)
def decrypt_hybrid_bundle(private_key, cipher_data: bytes) -> bytes:
    try:
        # cargar el "paquete" (bundle) desde JSON
        bundle = json.loads(cipher_data.decode('utf-8'))
        
        # convertir de .hex() (que era para el json) de nuevo a bytes
        encrypted_aes_key = bytes.fromhex(bundle['encrypted_aes_key'])
        iv = bytes.fromhex(bundle['iv'])
        ciphertext = bytes.fromhex(bundle['ciphertext'])
        aad = bytes.fromhex(bundle['aad'])

        # descifrar clave AES con RSA-OAEP para poder descifrar los datos
        aes_key = decrypt_with_private_key(private_key, encrypted_aes_key)
        
        # descifrar los datos con AES-GCM teniendo ya la clave AES
        plaintext = decrypt_aes_gcm(aes_key, iv, ciphertext, aad)
        
        logger.info("CLIENTE: Descifrado híbrido completado.")
        return plaintext

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.debug(f"CLIENTE: Descifrado híbrido fallido: Paquete corrupto o inválido. {e}")
        raise
    except Exception as e:
        logger.debug(f"CLIENTE: Descifrado híbrido fallido: {e}")
        raise