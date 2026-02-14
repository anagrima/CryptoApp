"""Compat wrapper para tickets: detecta formato (legacy vs hybrid) y despacha.

Este módulo contiene la implementación del despacho y expone la API que
usaba antes `src.tickets.__init__`.
"""
from pathlib import Path
import json
from typing import Any

from . import hybrid_encripted_store as hybrid
from . import store as legacy
from ..sign.sign_service import verify_transfer_authorization


# ruta usada por el store híbrido
TICKETS_DB_PATH = getattr(hybrid, "TICKETS_DB_PATH", None)


def _load_raw_db() -> dict:
    if TICKETS_DB_PATH is None:
        db_path = getattr(legacy, "DB_PATH", None)
        if db_path is None:
            return {}
        try:
            return json.loads(Path(db_path).read_text(encoding="utf-8"))
        except Exception:
            return {}
    try:
        return json.loads(Path(TICKETS_DB_PATH).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _detect_entry_type(username: str, ticket_id: str) -> str:
    db = _load_raw_db()
    user_entries = db.get(username, {})
    entry = user_entries.get(ticket_id)
    if entry is None:
        return "missing"
    if isinstance(entry, str):
        return "hybrid"
    if isinstance(entry, dict):
        return "legacy"
    return "unknown"


def list_user_tickets(username: str) -> list[str]:
    try:
        return hybrid.list_user_tickets(username)
    except Exception:
        try:
            return legacy.list_user_tickets(username)
        except Exception:
            return []


def add_ticket(ticket: Any) -> None:
    return hybrid.add_ticket(ticket)


def get_ticket_decrypted(username: str, ticket_id: str):
    ttype = _detect_entry_type(username, ticket_id)
    if ttype == "hybrid":
        return hybrid.get_ticket_decrypted(username, ticket_id)
    if ttype == "legacy":
        return legacy.get_ticket_decrypted(username, ticket_id)
    return None


def transfer_ticket_with_authorization(owner_username: str, new_owner_username: str, ticket_id: str, auth_wrapper: dict) -> None:
    ttype = _detect_entry_type(owner_username, ticket_id)
    # HYBRID flow
    if ttype == "hybrid":
        # verify ticket exists
        db = hybrid._load_ticket_db()
        owner_entries = db.get(owner_username, {})
        if ticket_id not in owner_entries:
            raise KeyError("Ticket no encontrado para el propietario")

        # obtener clave publica del owner para verificar la autorización
        owner_pub = hybrid.get_user_public_key(owner_username)
        if not owner_pub:
            raise RuntimeError("No se encontró la clave pública del propietario para verificar la autorización")

        ok = verify_transfer_authorization(auth_wrapper, owner_public_key_pem=owner_pub)
        if not ok:
            raise RuntimeError("Autorización de transferencia inválida")

        auth_payload = auth_wrapper.get("payload", {})
        new_owner_pub = hybrid.get_user_public_key(new_owner_username)
        if not new_owner_pub:
            raise RuntimeError("No se encontró la clave pública del nuevo propietario")
        if auth_payload.get("ticket_id") != ticket_id or auth_payload.get("new_owner_pubkey") != new_owner_pub:
            raise RuntimeError("El contenido de la autorización no coincide con la transferencia solicitada")

        # descifrar ticket con la clave privada local del propietario
        ticket = hybrid.get_ticket_decrypted(owner_username, ticket_id)
        if ticket is None:
            raise RuntimeError("No se pudo descifrar el ticket con la clave privada del propietario")

        # reasignar y re-encriptar para nuevo propietario
        ticket.username = new_owner_username
        hybrid.add_ticket(ticket)

        # eliminar entrada antigua
        db = hybrid._load_ticket_db()
        if owner_username in db and ticket_id in db[owner_username]:
            try:
                del db[owner_username][ticket_id]
                if not db[owner_username]:
                    del db[owner_username]
                hybrid._save_ticket_db(db)
            except Exception as e:
                hybrid.logger.debug(f"STORE: Fallo al eliminar ticket antiguo tras transferencia: {e}")
        return

    # LEGACY flow
    if ttype == "legacy":
        db = legacy._load_db()
        owner_entries = db.get(owner_username, {})
        if ticket_id not in owner_entries:
            raise KeyError("Ticket no encontrado para el propietario")

        owner_pub_pem = legacy.get_user_public_key_pem(owner_username)
        if not owner_pub_pem:
            raise RuntimeError("No se encontró la clave pública del propietario para verificar la autorización")

        ok = verify_transfer_authorization(auth_wrapper, owner_public_key_pem=owner_pub_pem)
        if not ok:
            raise RuntimeError("Autorización de transferencia inválida")

        auth_payload = auth_wrapper.get("payload", {})
        new_owner_pub = legacy.get_user_public_key_pem(new_owner_username)
        if not new_owner_pub:
            raise RuntimeError("No se encontró la clave pública del nuevo propietario")
        if auth_payload.get("ticket_id") != ticket_id or auth_payload.get("new_owner_pubkey") != new_owner_pub:
            raise RuntimeError("El contenido de la autorización no coincide con la transferencia solicitada")

        # desencriptar usando legacy
        ticket = legacy.get_ticket_decrypted(owner_username, ticket_id)
        # actualizar owner y re-encriptar usando legacy.add_ticket
        ticket.username = new_owner_username
        legacy.add_ticket(ticket)

        # eliminar entrada antigua
        db = legacy._load_db()
        try:
            del db[owner_username][ticket_id]
            if not db[owner_username]:
                del db[owner_username]
            legacy._save_db(db)
        except Exception as e:
            # registrar y continuar
            pass
        return

    raise KeyError("Ticket no encontrado para el propietario")
