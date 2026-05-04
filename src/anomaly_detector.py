import statistics
from typing import List, Tuple

from src.network_packet import NetworkPacket
from src.exceptions import InsufficientTrainingDataError, DetectionError


class AnomalyDetector:
    """
    Hybrid anomaly detection:
      1. Rule-based pass for obvious DDoS / port-scan patterns.
      2. Z-score statistical check against a trained baseline for borderline cases.
    Returns (label, confidence): label is 'normal' | 'suspicious' | 'ddos',
    confidence is a float 0.0–1.0.
    """

    DDOS_PPS_THRESHOLD = 300
    PORT_SCAN_FAILED_THRESHOLD = 20
    Z_SCORE_THRESHOLD = 2.5

    def __init__(self):
        self._baseline: dict = {}
        self._is_trained: bool = False

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def train(self, packets: List[NetworkPacket]) -> None:
        normal = [p for p in packets if p.label == "normal"]
        if len(normal) < 2:
            raise InsufficientTrainingDataError(
                f"Need at least 2 normal packets to train; got {len(normal)}."
            )
        for attr in ("packets_per_second", "bytes_per_second", "failed_connections"):
            values = [getattr(p, attr) for p in normal]
            self._baseline[attr] = {
                "mean": statistics.mean(values),
                "stdev": statistics.stdev(values) or 1.0,
            }
        self._is_trained = True

    def predict(self, packet: NetworkPacket) -> Tuple[str, float]:
        try:
            rule_label = self._rule_based_check(packet)
            if rule_label != "normal":
                return rule_label, 1.0

            if not self._is_trained:
                return "normal", 0.5

            max_z = max(
                self._z_score(
                    getattr(packet, attr),
                    self._baseline[attr]["mean"],
                    self._baseline[attr]["stdev"],
                )
                for attr in self._baseline
            )

            if max_z >= self.Z_SCORE_THRESHOLD:
                confidence = min(max_z / 5.0, 1.0)
                return "suspicious", round(confidence, 2)

            return "normal", round(1.0 - max_z / self.Z_SCORE_THRESHOLD, 2)

        except Exception as exc:
            raise DetectionError(f"Prediction failed for packet {packet.id}: {exc}") from exc

    def _rule_based_check(self, packet: NetworkPacket) -> str:
        if packet.packets_per_second >= self.DDOS_PPS_THRESHOLD:
            return "ddos"
        if packet.failed_connections >= self.PORT_SCAN_FAILED_THRESHOLD:
            return "suspicious"
        return "normal"

    @staticmethod
    def _z_score(value: float, mean: float, stdev: float) -> float:
        return abs(value - mean) / stdev