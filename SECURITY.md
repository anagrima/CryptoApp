# SECURITY

- **Passwords**: hash + salt con `bcrypt` y politica minima (longitud/smbolos).
- **AES-GCM (AEAD)**: IV aleatorio de 12 bytes, claves ≥128 bits.
- **HMAC-SHA256**: claves ≥128 bits.
- **Key storage**: derivacion con Scrypt y cifrado con AES-GCM.
- **Firmas**: RSA-PSS con SHA-256 (Eval2), claves ≥2048 bits.
- **PKI**: CA raiz y emision de certificados (Eval2).
- **Logging**: todas las operaciones registran algoritmo y tamaño de clave cuando aplica.