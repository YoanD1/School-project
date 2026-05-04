import random
from datetime import datetime

from src.network_packet import NetworkPacket


class TrafficSimulator:
    """Generates synthetic network packets for testing and live demos."""

    _NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
    _ATTACKER_IPS = ["45.33.32.156", "185.220.101.5", "203.0.113.50"]
    _PROTOCOLS = ["HTTP", "HTTPS", "DNS", "TCP", "UDP"]
    _PORTS = {"HTTP": 80, "HTTPS": 443, "DNS": 53, "TCP": 0, "UDP": 0}

    def generate_normal(self) -> NetworkPacket:
        protocol = random.choice(["HTTP", "HTTPS", "DNS"])
        return NetworkPacket(
            source_ip=random.choice(self._NORMAL_IPS),
            dest_ip=random.choice(["10.0.0.1", "10.0.0.2", "8.8.8.8"]),
            protocol=protocol,
            port=self._PORTS[protocol],
            packet_size=random.randint(100, 1400),
            packets_per_second=random.uniform(5, 50),
            bytes_per_second=random.uniform(2000, 70000),
            failed_connections=random.randint(0, 2),
            timestamp=datetime.now(),
            label="normal",
        )

    def generate_ddos(self) -> NetworkPacket:
        return NetworkPacket(
            source_ip=random.choice(self._ATTACKER_IPS),
            dest_ip=random.choice(self._NORMAL_IPS),
            protocol="TCP",
            port=0,
            packet_size=64,
            packets_per_second=random.uniform(500, 1500),
            bytes_per_second=random.uniform(300_000, 900_000),
            failed_connections=0,
            timestamp=datetime.now(),
            label="ddos",
        )

    def generate_port_scan(self) -> NetworkPacket:
        return NetworkPacket(
            source_ip=random.choice(self._ATTACKER_IPS),
            dest_ip=random.choice(self._NORMAL_IPS),
            protocol="TCP",
            port=random.randint(1, 65535),
            packet_size=60,
            packets_per_second=random.uniform(80, 200),
            bytes_per_second=random.uniform(5000, 15000),
            failed_connections=random.randint(20, 60),
            timestamp=datetime.now(),
            label="suspicious",
        )

    def generate_batch(self, total: int = 20, anomaly_ratio: float = 0.3) -> list:
        packets = []
        anomaly_count = int(total * anomaly_ratio)
        for _ in range(total - anomaly_count):
            packets.append(self.generate_normal())
        for i in range(anomaly_count):
            packets.append(self.generate_ddos() if i % 2 == 0 else self.generate_port_scan())
        random.shuffle(packets)
        return packets
