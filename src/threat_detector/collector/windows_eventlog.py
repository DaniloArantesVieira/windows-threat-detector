from datetime import datetime

import pywintypes
import win32evtlog

from threat_detector.models.event import SecurityEvent


class WindowsEventCollector:
    def __init__(self, log_name="Security", server=None):
        self.log_name = log_name
        self.server = server

    @staticmethod
    def _convert_timestamp(timestamp) -> datetime:
        return datetime(
            timestamp.year,
            timestamp.month,
            timestamp.day,
            timestamp.hour,
            timestamp.minute,
            timestamp.second,
        )

    @staticmethod
    def _get_string(strings, index):
        """
        Retorna um valor de StringInserts de forma segura.
        Valores vazios e "-" são convertidos para None.
        """

        if index >= len(strings):
            return None

        value = strings[index]

        if value in (None, "", "-"):
            return None

        return str(value)

    def _parse_failed_logon(self, event, strings):
        """
        Interpreta campos do Windows Event ID 4625.
        """

        event.subject_username = self._get_string(strings, 1)
        event.subject_domain = self._get_string(strings, 2)

        event.target_username = self._get_string(strings, 5)
        event.target_domain = self._get_string(strings, 6)

        event.status = self._get_string(strings, 7)
        event.failure_reason = self._get_string(strings, 8)
        event.substatus = self._get_string(strings, 9)

        logon_type = self._get_string(strings, 10)

        if logon_type is not None:
            try:
                event.logon_type = int(logon_type)
            except ValueError:
                event.logon_type = None

        event.logon_process = self._get_string(strings, 11)
        event.authentication_package = self._get_string(
            strings,
            12,
        )

        event.process_id = self._get_string(strings, 17)
        event.process_name = self._get_string(strings, 18)

        event.source_ip = self._get_string(strings, 19)
        event.source_port = self._get_string(strings, 20)

        # Campo de conveniência usado pelo Detection Engine.
        #
        # Normalmente o usuário alvo aparece em target_username.
        # Alguns tipos de autenticação local podem não preencher
        # esse campo, portanto usamos subject_username como fallback.
        event.username = (
            event.target_username
            or event.subject_username
        )

    def get_events(self, limit=10, event_ids=None):
        handle = None
        collected_events: list[SecurityEvent] = []

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        try:
            handle = win32evtlog.OpenEventLog(
                self.server,
                self.log_name,
            )

            while len(collected_events) < limit:
                events = win32evtlog.ReadEventLog(
                    handle,
                    flags,
                    0,
                )

                if not events:
                    break

                for raw_event in events:
                    event_id = raw_event.EventID & 0xFFFF

                    if event_ids and event_id not in event_ids:
                        continue

                    strings = (
                        list(raw_event.StringInserts)
                        if raw_event.StringInserts
                        else []
                    )

                    event = SecurityEvent(
                        event_id=event_id,
                        timestamp=self._convert_timestamp(
                            raw_event.TimeGenerated
                        ),
                        computer=raw_event.ComputerName,
                        channel=self.log_name,
                        source=raw_event.SourceName,
                        event_type=raw_event.EventType,
                        strings=strings,
                    )

                    if event_id == 4625:
                        self._parse_failed_logon(
                            event,
                            strings,
                        )

                    collected_events.append(event)

                    if len(collected_events) >= limit:
                        break

            return collected_events

        except pywintypes.error as error:
            error_code = (
                error.args[0]
                if error.args
                else None
            )

            if error_code in (5, 1314):
                raise PermissionError(
                    "Sem permissão para acessar o Windows "
                    "Security Event Log. Execute o PowerShell "
                    "como Administrador."
                ) from error

            raise RuntimeError(
                f"Erro ao acessar o Windows Event Log: {error}"
            ) from error

        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)