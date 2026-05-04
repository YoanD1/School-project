from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class NetworkPacket:
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    packet_size: int
    packets_per_second: float
    bytes_per_second: float
    failed_connections: int
    timestamp: datetime = field(default_factory=datetime.now)
    id: Optional[int] = None
    label: str = "normal"
    device_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "port": self.port,
            "packet_size": self.packet_size,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "failed_connections": self.failed_connections,
            "timestamp": self.timestamp.isoformat(),
            "label": self.label,
            "device_id": self.device_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkPacket":
        data = data.copy()
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)

    def __str__(self) -> str:
        return (
            f"[{self.timestamp.strftime('%H:%M:%S')}] "
            f"{self.source_ip} -> {self.dest_ip} | "
            f"{self.protocol}:{self.port} | "
            f"{self.packets_per_second} pps | label={self.label}"
        )
