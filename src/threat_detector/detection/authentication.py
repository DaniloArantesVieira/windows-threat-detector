from collections import defaultdict
from datetime import timedelta

from threat_detector.mitre.mappings import MITRE_MAPPINGS
from threat_detector.models.alert import Alert
from threat_detector.models.event import SecurityEvent


class AuthenticationDetector:
    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 300,
    ):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def analyze(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """
        Analisa eventos 4625 e procura múltiplas falhas
        para o mesmo usuário e origem dentro de uma
        janela de tempo.
        """

        groups = defaultdict(list)

        for event in events:
            if event.event_id != 4625:
                continue

            username = event.username or "UNKNOWN"
            source_ip = event.source_ip or "UNKNOWN"

            key = (
                username.lower(),
                source_ip.lower(),
            )

            groups[key].append(event)

        alerts = []

        for group_events in groups.values():
            group_events.sort(
                key=lambda event: event.timestamp
            )

            alert = self._analyze_group(group_events)

            if alert:
                alerts.append(alert)

        return alerts

    def _analyze_group(
        self,
        events: list[SecurityEvent],
    ) -> Alert | None:
        if len(events) < self.threshold:
            return None

        left = 0

        best_count = 0
        best_start = 0
        best_end = 0

        for right in range(len(events)):
            while (
                events[right].timestamp
                - events[left].timestamp
                > self.window
            ):
                left += 1

            count = right - left + 1

            if count > best_count:
                best_count = count
                best_start = left
                best_end = right

        if best_count < self.threshold:
            return None

        first_event = events[best_start]
        last_event = events[best_end]

        mitre = MITRE_MAPPINGS["brute_force"]

        return Alert(
            title="Possível ataque de força bruta",
            severity="HIGH",
            description=(
                f"{best_count} falhas de autenticação "
                f"foram detectadas dentro da janela "
                f"configurada."
            ),
            event_id=4625,
            timestamp=last_event.timestamp,
            username=last_event.username,
            source_ip=last_event.source_ip,
            count=best_count,
            first_seen=first_event.timestamp,
            last_seen=last_event.timestamp,
            mitre_id=mitre["id"],
            mitre_technique=mitre["technique"],
        )