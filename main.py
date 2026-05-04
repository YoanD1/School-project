import csv
import os
from datetime import datetime

from src.network_packet import NetworkPacket
from src.anomaly_detector import AnomalyDetector
from src.traffic_analyzer import TrafficAnalyzer
from src.event_manager import EventManager
from src.database_service import DatabaseService
from src.file_logger import FileLogger
from src.monitoring_service import MonitoringService
from src.traffic_simulator import TrafficSimulator
from src.exceptions import NetworkMonitorError, InsufficientTrainingDataError


def load_csv(path: str) -> list:
    packets = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            packets.append(NetworkPacket(
                id=int(row["id"]),
                source_ip=row["source_ip"],
                dest_ip=row["dest_ip"],
                protocol=row["protocol"],
                port=int(row["port"]),
                packet_size=int(row["packet_size"]),
                packets_per_second=float(row["packets_per_second"]),
                bytes_per_second=float(row["bytes_per_second"]),
                failed_connections=int(row["failed_connections"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                label=row["label"],
            ))
    return packets


def main():
    # Remove stale DB so each run starts clean
    db_path = "db/network_monitor.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    logger = FileLogger()
    db = DatabaseService(db_path)
    events = EventManager()
    detector = AnomalyDetector()
    analyzer = TrafficAnalyzer()
    service = MonitoringService(detector, analyzer, events, db, logger)

    # --- Train the detector on known-normal traffic ---
    logger.info("Loading sample data for training...")
    try:
        all_packets = load_csv("data/sample_traffic.csv")
        normal_packets = [p for p in all_packets if p.label == "normal"]
        detector.train(normal_packets)
        logger.info(f"Detector trained on {len(normal_packets)} normal packets.")
    except InsufficientTrainingDataError as exc:
        logger.error(f"Training failed: {exc}")
        return
    except NetworkMonitorError as exc:
        logger.error(f"Startup error: {exc}")
        return

    # --- Process the full sample dataset ---
    print("\n--- Processing sample dataset ---")
    service.process_batch(all_packets)

    # --- Live simulation (Week 3 will extend this) ---
    print("\n--- Running live simulation (10 packets) ---")
    simulator = TrafficSimulator()
    live_packets = simulator.generate_batch(total=10, anomaly_ratio=0.4)
    service.process_batch(live_packets)

    # --- Print summary and export ---
    service.print_summary()

    suspicious = analyzer.get_suspicious_packets()
    logger.export_to_json([p.to_dict() for p in suspicious], "anomalies_export.json")
    logger.export_to_csv([p.to_dict() for p in suspicious], "anomalies_export.csv")


if __name__ == "__main__":
    main()
