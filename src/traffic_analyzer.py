from functools import reduce
from itertools import groupby
from typing import Dict, List, Tuple

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

    # --- reduce-based aggregations ---

    def total_bytes_transferred(self) -> float:
        """Sum of bytes_per_second across all packets using reduce."""
        if not self.packets:
            return 0.0
        return reduce(lambda acc, p: acc + p.bytes_per_second, self.packets, 0.0)

    def total_failed_connections(self) -> int:
        """Sum of failed_connections across all packets using reduce."""
        if not self.packets:
            return 0
        return reduce(lambda acc, p: acc + p.failed_connections, self.packets, 0)

    # --- map-based transformations ---

    def risk_scores(self) -> List[Tuple[str, float]]:
        """Map each packet to (source_ip, risk_score). Score = pps*0.4 + failed*2."""
        return list(map(
            lambda p: (p.source_ip, round(p.packets_per_second * 0.4 + p.failed_connections * 2.0, 1)),
            self.packets,
        ))

    def get_critical_ips(self, risk_threshold: float = 80.0) -> List[str]:
        """Filter IPs whose risk score exceeds the threshold (filter + map combo)."""
        scored = filter(lambda x: x[1] >= risk_threshold, self.risk_scores())
        return sorted(set(map(lambda x: x[0], scored)))
