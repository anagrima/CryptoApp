import json
from pathlib import Path
from typing import List, Dict, Any
from ..config import DATA_PATH, load_or_create_tickets_key
from ..crypto.symmetric import encrypt_aes_gcm, decrypt_aes_gcm
from .models import Ticket
from ..sign.sign_service import sign_ticket_payload, verify_transfer_authorization, append_sign_log
from ..auth.user_store import get_user_public_key_pem

DB_PATH = Path(DATA_PATH) / "tickets.db"

def _load_db() -> Dict[str, Any]:
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        # simple fallback: reinicia (o podrias respaldar .corrupt como en user_store)
        return {}

def _save_db(db: Dict[str, Any]) -> None:
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

def add_ticket(ticket: Ticket) -> None:
    key = load_or_create_tickets_key()
    aad = f"{ticket.username}|{ticket.ticket_id}".encode("utf-8")
    payload = {
        "ticket_id": ticket.ticket_id,
        "username": ticket.username,
        "artist": ticket.artist,
        "venue": ticket.venue,
        "date_iso": ticket.date_iso,
        "seat": ticket.seat,
        "qr_payload": ticket.qr_payload,
    }
    # añadir firma de emisión por parte del servidor (issuer)
    try:
        issuer_sig = sign_ticket_payload(payload)
        payload["issuer_signature"] = issuer_sig
    except Exception as e:
        # si por alguna razon falla la firma --> registrar y seguir (o decidir fail-fast)
        raise RuntimeError(f"No se pudo firmar el ticket: {e}")
    pt = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    enc = encrypt_aes_gcm(key, pt, aad=aad)
    db = _load_db()
    db.setdefault(ticket.username, {})
    db[ticket.username][ticket.ticket_id] = {
        "iv": enc["iv"].hex(),
        "ciphertext": enc["ciphertext"].hex(),
        "aad": enc["aad"].decode("utf-8") if isinstance(enc["aad"], (bytes, bytearray)) else enc["aad"],
    }
    _save_db(db)

# lista los IDs de tickets para un usuario dado
def list_user_tickets(username: str) -> List[str]:
    db = _load_db()
    return list(db.get(username, {}).keys())

# obtiene y descifra un ticket para un usuario dado
def get_ticket_decrypted(username: str, ticket_id: str) -> Ticket:
    key = load_or_create_tickets_key()
    db = _load_db()
    entry = db.get(username, {}).get(ticket_id)
    if not entry:
        raise KeyError("Ticket no encontrado")
    iv = bytes.fromhex(entry["iv"])
    ct = bytes.fromhex(entry["ciphertext"])
    aad = entry["aad"].encode("utf-8")
    pt = decrypt_aes_gcm(key, iv, ct, aad=aad)
    obj = json.loads(pt.decode("utf-8"))
    return Ticket(**obj)
