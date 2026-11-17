"""Write one JSON object per line (JSON Lines). Easy to grep, easy to load in a SIEM."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone


class EventLogger:
    def __init__(self, path: str, echo: bool = True):
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()

    def log(self, event: str, ip: str, **fields) -> None:
        record = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "event": event, "ip": ip, **fields}
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            if self.echo:
                details = " ".join(f"{k}={v!r}" for k, v in fields.items())
                print(f"{record['time']} {event:<14} {ip:<15} {details}", flush=True)
