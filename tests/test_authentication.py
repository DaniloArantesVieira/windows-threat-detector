from datetime import datetime, timedelta

from threat_detector.detection.authentication import (
    AuthenticationDetector,
)
from threat_detector.models.event import SecurityEvent


def create_failed_logon(
    timestamp: datetime,
    username: str = "teste",
    source_ip: str = "192.168.1.100",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=4625,
        timestamp=timestamp,
        computer="LAB-WINDOWS",
        channel="Security",
        username=username,
        source_ip=source_ip,
    )


def test_three_failures_do_not_generate_alert():
    detector = AuthenticationDetector(
        threshold=10,
        window_seconds=300,
    )

    start = datetime(2026, 9, 7, 10, 0, 0)

    events = [
        create_failed_logon(
            start + timedelta(seconds=index * 30)
        )
        for index in range(3)
    ]

    alerts = detector.analyze(events)

    assert alerts == []


def test_ten_failures_generate_brute_force_alert():
    detector = AuthenticationDetector(
        threshold=10,
        window_seconds=300,
    )

    start = datetime(2026, 9, 7, 10, 0, 0)

    events = [
        create_failed_logon(
            start + timedelta(seconds=index * 20)
        )
        for index in range(10)
    ]

    alerts = detector.analyze(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.title == "Possível ataque de força bruta"
    assert alert.severity == "HIGH"
    assert alert.event_id == 4625

    assert alert.username == "teste"
    assert alert.source_ip == "192.168.1.100"

    assert alert.count == 10

    assert alert.mitre_id == "T1110"
    assert alert.mitre_technique == "Brute Force"


def test_failures_outside_time_window_do_not_generate_alert():
    detector = AuthenticationDetector(
        threshold=10,
        window_seconds=300,
    )

    start = datetime(2026, 9, 7, 10, 0, 0)

    events = [
        create_failed_logon(
            start + timedelta(minutes=index)
        )
        for index in range(10)
    ]

    alerts = detector.analyze(events)

    assert alerts == []


def test_different_source_ips_are_not_combined():
    detector = AuthenticationDetector(
        threshold=10,
        window_seconds=300,
    )

    start = datetime(2026, 9, 7, 10, 0, 0)

    events = []

    for index in range(5):
        events.append(
            create_failed_logon(
                start + timedelta(seconds=index * 20),
                source_ip="192.168.1.100",
            )
        )

    for index in range(5):
        events.append(
            create_failed_logon(
                start + timedelta(seconds=index * 20),
                source_ip="192.168.1.200",
            )
        )

    alerts = detector.analyze(events)

    assert alerts == []