## instalacion en Visual Studio Code
py -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
.\.venv\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt


## ejecucion app tickets

# Linux
ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" python -m client.main

# Windows CMD
set ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" && python -m client.main

# PowerShell (no copiar la almohadilla)
# $env:ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" ; python -m client.main


## ejecucion tests

# Linux
ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" python -m pytest -q

# Windows CMD
set ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" && python -m pytest -q

# PowerShell (no copiar la almohadilla)
# $env:ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" ; python -m pytest -q


## estructura del proyecto
CryptoApp/
|--README.md
|--SECURITY.md
|--requirements.txt
|--pyproject.toml
|--.env.example
|--client/
|   |--mock_client_keys/
|   |--client_app.py
|   |--client_setup.py
|   |--main.py
|   |--sms_app.py
|--data/
|   keystore/
|   |	|--issuer_private.pem
|   |	|--issuer_public.pem
|   |--aes_tickets.key
|   |--tickets.db
|   |--users.db
|--logs_sign/
|   |--signatures.log
|--src/
|   |--config.py
|   |--logger.py
|   |--auth/
|   |   |--auth_service.py
|   |   |--password_policy.py
|   |   |--short_message_service.py
|   |   |--user_store.py
|   |--common/
|   |   |--constants.py
|   |   |--validators.py
|   |--crypto/
|   |   |--asymmetric.py
|   |   |--hybrid.py
|   |   |--mac.py
|   |   |--symmetric.py
|   |--tickets/
|   |   |--compat.py
|   |   |--hybrid_encripted_store.py
|   |   |--models.py
|   |   |--store.py
|   |--pki
|   |   |--pki_AC_root.py
|   |   |--pki_AC_subordinate.py
|   |	|--pki_certificate_actions.py
|   |   |--pki_init.py
|   |   |--pki_user.py
|   |   |--pli_store.py
|   |--sign
|   |   |--sign_service.py
|--tests/
        |--conftest.py
        |--test_auth.py
        |--test_crypto.py
        |--test_hybrid.py
        |--test_mac.py
	|--test_pki.py
        |--test_sign.py
        |--test_sms.py
        |--test_tickets.py
        |--test_validators.py


## autores
Ana Grima Vázquez de Prada y Blanca Peña Moñino
