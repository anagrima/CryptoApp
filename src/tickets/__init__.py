"""gestor de tickets

Este paquete expone la API unificada de tickets. La implementación de compatibilidad
está en `src.tickets.compat` y aquí reexportamos sus símbolos para mantener la
compatibilidad con importaciones existentes como `from src.tickets import ...`.
"""
from .compat import *