# TicketsCifrados-Criptografia

# Autoras
Ana Grima Vázquez de Prada y Blanca Peña Moñino

# Instalacion en Visual Studio Code
py -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
.\.venv\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt


# Ejecucion app tickets

## Linux
ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" python -m client.main

## Windows CMD
set ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" && python -m client.main

## PowerShell
$env:ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" ; python -m client.main


# ejecucion tests

## Linux
ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" python -m pytest -q

## Windows CMD
set ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" && python -m pytest -q

## PowerShell
$env:ISSUER_KEY_PASSWORD="UnaClaveParaPruebas123" ; python -m pytest -q
