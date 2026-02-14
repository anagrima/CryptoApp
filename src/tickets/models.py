from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
import json


@dataclass
class Ticket:
    ticket_id: str
    username: str
    artist: str
    venue: str
    date_iso: str  # ISO 8601 "2025-11-21T20:00:00"
    seat: str
    qr_payload: str  # texto QR (o id)
    issuer_signature: Optional[dict] = None

    def __post_init__(self):
        # validar que ningun campo obligatorio sea vacio o None (ignorar issuer_signature)
        for field in ("ticket_id", "username", "artist", "venue", "date_iso", "seat", "qr_payload"):
            value = getattr(self, field)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                raise ValueError(f"El campo '{field}' es obligatorio y no puede estar vacío o ser None")

    # funciones para serializar y deserializar el ticket (para poder enviarlo cifrado)
    def to_json_bytes(self) -> bytes:
        return json.dumps(asdict(self), ensure_ascii=False).encode('utf-8')

    @staticmethod
    def from_json_bytes(data: bytes):
        payload = json.loads(data.decode('utf-8'))
        return Ticket(**payload)
