import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# funcion para generar un par de claves RSA
def generate_key_pair(key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# funcion para encriptar datos usando RSA-OAEP
def encrypt_with_public_key(public_key, plaintext: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        plaintext,

        # uso de OAEP para solucionar problemas de determinismo y maleabilidad
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# funcion para desencriptar usando RSA-OAEP
def decrypt_with_private_key(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,

        # hay que tener en cuenta el mismo padding y parametros que en la encriptacion
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# FUNCIONES PARA SERIALIZAR Y DESERIALIZAR CLAVES A FORMATO PEM, Y PODER ENVIARLAS Y ALMACENARLAS
def serialize_public_key(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_public_key(pem_data: str):
    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=default_backend()
    )

def serialize_private_key(private_key, password: bytes = None) -> str:
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    return pem.decode('utf-8')

def deserialize_private_key(pem_data: str, password: bytes = None):
    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=password,
        backend=default_backend()
    )