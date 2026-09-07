from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SecurityEvent:
    event_id: int
    timestamp: datetime
    computer: str
    channel: str

    source: str | None = None
    event_type: int | None = None

    # Autenticação
    username: str | None = None

    subject_username: str | None = None
    subject_domain: str | None = None

    target_username: str | None = None
    target_domain: str | None = None

    logon_type: int | None = None
    logon_process: str | None = None
    authentication_package: str | None = None

    status: str | None = None
    substatus: str | None = None
    failure_reason: str | None = None

    # Rede
    source_ip: str | None = None
    source_port: str | None = None

    # Processo
    process_id: str | None = None
    process_name: str | None = None
    command_line: str | None = None

    strings: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)