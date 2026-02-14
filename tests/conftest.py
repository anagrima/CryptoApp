# tests/conftest.py
import sys
import os

# Añade el directorio raíz del proyecto (el padre de 'tests/') al sys.path
# Esto permite que los tests importen 'src' como un módulo.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)