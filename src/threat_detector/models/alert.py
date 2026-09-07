from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    title: str
    severity: str
    description: str

    event_id: int
    timestamp: datetime

    username: str | None = None
    source_ip: str | None = None

    count: int = 1

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    mitre_id: str | None = None
    mitre_technique: str | None = None