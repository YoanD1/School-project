from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List


# --- Custom Event Args ---

@dataclass
class EventArgs:
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""


@dataclass
class AnomalyEventArgs(EventArgs):
    packet_id: int = 0
    anomaly_type: str = ""
    severity: str = "low"
    source_ip: str = ""


@dataclass
class DDoSEventArgs(EventArgs):
    attacker_ip: str = ""
    target_ip: str = ""
    packets_per_second: float = 0.0


@dataclass
class UnusualTrafficEventArgs(EventArgs):
    description: str = ""
    device_ip: str = ""
    protocol: str = ""


# --- Event Manager (Observer pattern) ---

class EventManager:
    ON_ANOMALY_DETECTED = "on_anomaly_detected"
    ON_DDOS_SUSPECTED = "on_ddos_suspected"
    ON_UNUSUAL_TRAFFIC = "on_unusual_traffic"

    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = {
            self.ON_ANOMALY_DETECTED: [],
            self.ON_DDOS_SUSPECTED: [],
            self.ON_UNUSUAL_TRAFFIC: [],
        }

    def subscribe(self, event: str, callback: Callable) -> None:
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def unsubscribe(self, event: str, callback: Callable) -> None:
        if event in self._listeners:
            self._listeners[event].remove(callback)

    def dispatch(self, event: str, args: EventArgs) -> None:
        for callback in self._listeners.get(event, []):
            callback(args)
