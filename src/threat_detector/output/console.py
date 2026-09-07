from threat_detector.models.alert import Alert


def print_alert(alert: Alert):
    print()
    print("=" * 70)
    print("WINDOWS THREAT DETECTOR - ALERTA")
    print("=" * 70)

    print(f"Severidade     : {alert.severity}")
    print(f"Título         : {alert.title}")
    print(f"Descrição      : {alert.description}")

    print()
    print("Evidências")
    print("-" * 70)

    print(f"Event ID       : {alert.event_id}")
    print(f"Usuário        : {alert.username}")
    print(f"IP de origem   : {alert.source_ip}")
    print(f"Tentativas     : {alert.count}")
    print(f"Primeiro evento: {alert.first_seen}")
    print(f"Último evento  : {alert.last_seen}")

    print()
    print("MITRE ATT&CK")
    print("-" * 70)

    print(f"Técnica        : {alert.mitre_id}")
    print(f"Nome           : {alert.mitre_technique}")

    print("=" * 70)