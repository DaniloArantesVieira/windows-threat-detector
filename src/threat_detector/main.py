from threat_detector.collector.windows_eventlog import (
    WindowsEventCollector,
)
from threat_detector.detection.authentication import (
    AuthenticationDetector,
)
from threat_detector.output.console import print_alert
from threat_detector.settings import load_config


def main():
    print("Windows Threat Detector v0.1")
    print("[*] Inicializando detector...")

    try:
        config = load_config()

    except (FileNotFoundError, RuntimeError) as error:
        print(f"[ERRO] {error}")
        return

    brute_force_config = (
        config
        .get("authentication", {})
        .get("brute_force", {})
    )

    if not brute_force_config.get("enabled", False):
        print(
            "[!] Detecção de força bruta está desativada."
        )
        return

    threshold = brute_force_config.get(
        "threshold",
        10,
    )

    window_seconds = brute_force_config.get(
        "window_seconds",
        300,
    )

    event_id = brute_force_config.get(
        "event_id",
        4625,
    )

    collector = WindowsEventCollector(
        log_name="Security"
    )

    detector = AuthenticationDetector(
        threshold=threshold,
        window_seconds=window_seconds,
    )

    print(
        f"[*] Regra carregada: "
        f"{threshold} falhas em "
        f"{window_seconds} segundos."
    )

    print(
        f"[*] Coletando falhas de autenticação "
        f"(Event ID {event_id})..."
    )

    try:
        events = collector.get_events(
            limit=50,
            event_ids={event_id},
        )

    except PermissionError as error:
        print(f"[ERRO] {error}")
        return

    except RuntimeError as error:
        print(f"[ERRO] {error}")
        return

    print(
        f"[+] {len(events)} falhas de autenticação "
        "encontradas."
    )

    print("[*] Executando análise de correlação...")

    alerts = detector.analyze(events)

    if not alerts:
        print(
            "[OK] Nenhum padrão de força bruta "
            "detectado."
        )
        return

    print(
        f"[!] {len(alerts)} alerta(s) "
        "de segurança detectado(s)."
    )

    for alert in alerts:
        print_alert(alert)


if __name__ == "__main__":
    main()