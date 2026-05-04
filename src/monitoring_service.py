from src.network_packet import NetworkPacket
from src.anomaly_detector import AnomalyDetector
from src.traffic_analyzer import TrafficAnalyzer
from src.event_manager import (
    EventManager,
    AnomalyEventArgs,
    DDoSEventArgs,
    UnusualTrafficEventArgs,
)
from src.database_service import DatabaseService
from src.file_logger import FileLogger
from src.exceptions import DetectionError, DatabaseError


class MonitoringService:
    """
    Central orchestrator. Accepts packets one at a time, runs them through
    the detector, fires the appropriate events, and persists results.
    """

    UNUSUAL_BPS_THRESHOLD = 80_000

    def __init__(
        self,
        detector: AnomalyDetector,
        analyzer: TrafficAnalyzer,
        events: EventManager,
        db: DatabaseService,
        logger: FileLogger,
    ):
        self._detector = detector
        self._analyzer = analyzer
        self._events = events
        self._db = db
        self._logger = logger
        self._register_callbacks()

    # ------------------------------------------------------------------
    # Named callbacks (minimum 2 per event as required)
    # ------------------------------------------------------------------

    def _on_anomaly_console(self, args: AnomalyEventArgs) -> None:
        print(
            f"  [ALERT] Anomaly | type={args.anomaly_type} "
            f"severity={args.severity} ip={args.source_ip}"
        )

    def _on_anomaly_log(self, args: AnomalyEventArgs) -> None:
        self._logger.warning(
            f"Anomaly recorded: type={args.anomaly_type} ip={args.source_ip}"
        )

    def _on_ddos_console(self, args: DDoSEventArgs) -> None:
        print(
            f"  [CRITICAL] DDoS suspected | "
            f"{args.attacker_ip} -> {args.target_ip} | {args.packets_per_second} pps"
        )

    def _on_ddos_log(self, args: DDoSEventArgs) -> None:
        self._logger.error(
            f"DDoS attack: attacker={args.attacker_ip} target={args.target_ip}"
        )

    def _on_unusual_console(self, args: UnusualTrafficEventArgs) -> None:
        print(
            f"  [WARNING] Unusual traffic | "
            f"{args.description} | device={args.device_ip} protocol={args.protocol}"
        )

    def _on_unusual_log(self, args: UnusualTrafficEventArgs) -> None:
        self._logger.warning(f"Unusual traffic: {args.description} from {args.device_ip}")

    def _register_callbacks(self) -> None:
        self._events.subscribe(EventManager.ON_ANOMALY_DETECTED, self._on_anomaly_console)
        self._events.subscribe(EventManager.ON_ANOMALY_DETECTED, self._on_anomaly_log)
        self._events.subscribe(EventManager.ON_DDOS_SUSPECTED, self._on_ddos_console)
        self._events.subscribe(EventManager.ON_DDOS_SUSPECTED, self._on_ddos_log)
        self._events.subscribe(EventManager.ON_UNUSUAL_TRAFFIC, self._on_unusual_console)
        self._events.subscribe(EventManager.ON_UNUSUAL_TRAFFIC, self._on_unusual_log)

    # ------------------------------------------------------------------
    # Core processing
    # ------------------------------------------------------------------

    def process_packet(self, packet: NetworkPacket) -> None:
        try:
            device_id = self._db.upsert_device(packet.source_ip)
            packet.device_id = device_id
        except DatabaseError as exc:
            self._logger.error(f"Device upsert failed: {exc}")

        try:
            label, confidence = self._detector.predict(packet)
            packet.label = label
        except DetectionError as exc:
            self._logger.error(f"Detection error: {exc}")
            label, confidence = "normal", 0.0

        try:
            packet_id = self._db.insert_packet(packet)
        except DatabaseError as exc:
            self._logger.error(f"Packet insert failed: {exc}")
            packet_id = -1

        self._analyzer.add_packet(packet)
        self._fire_event(packet, packet_id, label, confidence)

    def process_batch(self, packets: list) -> None:
        for packet in packets:
            self.process_packet(packet)

    def _fire_event(
        self,
        packet: NetworkPacket,
        packet_id: int,
        label: str,
        confidence: float,
    ) -> None:
        if label == "ddos":
            try:
                self._db.insert_anomaly(packet_id, "ddos", "high", f"DDoS from {packet.source_ip}")
            except DatabaseError as exc:
                self._logger.error(str(exc))
            self._events.dispatch(
                EventManager.ON_DDOS_SUSPECTED,
                DDoSEventArgs(
                    attacker_ip=packet.source_ip,
                    target_ip=packet.dest_ip,
                    packets_per_second=packet.packets_per_second,
                ),
            )

        elif label == "suspicious":
            severity = "high" if packet.failed_connections >= 30 else "medium"
            try:
                self._db.insert_anomaly(
                    packet_id, "suspicious", severity, f"Suspicious from {packet.source_ip}"
                )
            except DatabaseError as exc:
                self._logger.error(str(exc))
            self._events.dispatch(
                EventManager.ON_ANOMALY_DETECTED,
                AnomalyEventArgs(
                    packet_id=packet_id,
                    anomaly_type="suspicious",
                    severity=severity,
                    source_ip=packet.source_ip,
                ),
            )

        elif packet.bytes_per_second > self.UNUSUAL_BPS_THRESHOLD:
            try:
                self._db.insert_anomaly(packet_id, "unusual_traffic", "low", "High bandwidth")
            except DatabaseError as exc:
                self._logger.error(str(exc))
            self._events.dispatch(
                EventManager.ON_UNUSUAL_TRAFFIC,
                UnusualTrafficEventArgs(
                    description="High bandwidth usage",
                    device_ip=packet.source_ip,
                    protocol=packet.protocol,
                ),
            )

    def print_summary(self) -> None:
        print("\n" + "=" * 50)
        print("TRAFFIC SUMMARY")
        print("=" * 50)
        print("Anomaly counts    :", self._analyzer.anomaly_summary())
        print("Top 5 source IPs  :", self._analyzer.get_top_source_ips())
        print("High traffic (pps>=100):", len(self._analyzer.get_high_traffic_packets()))
        print("Avg packet size   :", round(self._analyzer.average_packet_size(), 1), "bytes")
        groups = self._analyzer.get_packets_by_protocol()
        print("By protocol       :", {k: len(v) for k, v in groups.items()})

        open_anomalies = self._db.get_open_anomalies()
        print(f"Open anomalies in DB: {len(open_anomalies)}")
        print("=" * 50)
