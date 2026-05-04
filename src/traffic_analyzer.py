from itertools import groupby
from typing import Dict, List

from src.network_packet import NetworkPacket


class TrafficAnalyzer:
    """Controller that applies LINQ-style analysis over a list of packets."""

    def __init__(self, packets: List[NetworkPacket] = None):
        self.packets: List[NetworkPacket] = packets or []

    def add_packet(self, packet: NetworkPacket) -> None:
        self.packets.append(packet)

    # --- LINQ-style operations ---

    def get_suspicious_packets(self) -> List[NetworkPacket]:
        return [p for p in self.packets if p.label != "normal"]

    def get_top_source_ips(self, n: int = 5) -> List[tuple]:
        ip_counts: Dict[str, int] = {}
        for p in self.packets:
            ip_counts[p.source_ip] = ip_counts.get(p.source_ip, 0) + 1
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_packets_by_protocol(self) -> Dict[str, List[NetworkPacket]]:
        sorted_packets = sorted(self.packets, key=lambda p: p.protocol)
        return {
            protocol: list(group)
            for protocol, group in groupby(sorted_packets, key=lambda p: p.protocol)
        }

    def get_high_traffic_packets(self, pps_threshold: float = 100) -> List[NetworkPacket]:
        return sorted(
            filter(lambda p: p.packets_per_second >= pps_threshold, self.packets),
            key=lambda p: p.packets_per_second,
            reverse=True,
        )

    def average_packet_size(self) -> float:
        if not self.packets:
            return 0.0
        return sum(p.packet_size for p in self.packets) / len(self.packets)

    def anomaly_summary(self) -> Dict[str, int]:
        labels = [p.label for p in self.packets]
        return {label: labels.count(label) for label in set(labels)}
