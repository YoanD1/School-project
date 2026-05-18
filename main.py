import csv
import os
from datetime import datetime

from src.network_packet import NetworkPacket
from src.anomaly_detector import AnomalyDetector
from src.model_evaluator import ModelEvaluator
from src.traffic_analyzer import TrafficAnalyzer
from src.event_manager import EventManager
from src.database_service import DatabaseService
from src.file_logger import FileLogger
from src.monitoring_service import MonitoringService
from src.traffic_simulator import TrafficSimulator
from src.exceptions import NetworkMonitorError, InsufficientTrainingDataError, DatabaseError


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
    # ── setup ────────────────────────────────────────────────────────────────
    db_path = "db/network_monitor.db"
    os.makedirs("db", exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    logger   = FileLogger()
    db       = DatabaseService(db_path)
    events   = EventManager()
    detector = AnomalyDetector()
    analyzer = TrafficAnalyzer()
    service  = MonitoringService(detector, analyzer, events, db, logger)

    # ── WEEK 3 · STEP 1 — Train AI model on labeled CSV data ────────────────
    print("\n" + "=" * 55)
    print("  WEEK 3 — AI + Data + DB + File + Analysis")
    print("=" * 55)

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

    # ── WEEK 3 · STEP 2 — Process full labeled dataset through the pipeline ─
    print("\n--- Processing labeled dataset (35 packets) ---")
    service.process_batch(all_packets)

    # ── WEEK 3 · STEP 3 — AI Model Evaluation (real vs predicted) ───────────
    evaluator = ModelEvaluator(detector)
    evaluator.print_report(all_packets)

    # ── WEEK 3 · STEP 4 — Live simulation (new unseen traffic) ──────────────
    print("\n--- Running live simulation (20 packets) ---")
    simulator = TrafficSimulator()
    live_packets = simulator.generate_batch(total=20, anomaly_ratio=0.35)
    service.process_batch(live_packets)

    # ── WEEK 3 · STEP 5 — LINQ-style analysis ───────────────────────────────
    print("\n--- LINQ-style Analysis ---")

    # list comprehension
    high_risk = [p for p in analyzer.packets if p.packets_per_second > 200]
    print(f"  High-risk packets (pps > 200)     : {len(high_risk)}")

    # map
    risk_scores = analyzer.risk_scores()
    top_risks = sorted(risk_scores, key=lambda x: x[1], reverse=True)[:5]
    print(f"  Top 5 risk scores (map)           : {top_risks}")

    # filter
    critical_ips = analyzer.get_critical_ips(risk_threshold=80.0)
    print(f"  Critical IPs (filter, risk>=80)   : {critical_ips}")

    # reduce
    total_bps = analyzer.total_bytes_transferred()
    total_failed = analyzer.total_failed_connections()
    print(f"  Total bytes/s transferred (reduce): {total_bps:,.0f}")
    print(f"  Total failed connections (reduce) : {total_failed}")

    # sorted + groupby
    service.print_summary()

    # ── WEEK 3 · STEP 6 — File export (JSON + CSV) ──────────────────────────
    suspicious = analyzer.get_suspicious_packets()
    logger.export_to_json([p.to_dict() for p in suspicious], "anomalies_export.json")
    logger.export_to_csv([p.to_dict() for p in suspicious],  "anomalies_export.csv")

    # ── WEEK 3 · STEP 7 — Read files back and verify ────────────────────────
    print("\n--- Reading exported files back ---")
    json_data = logger.read_from_json("anomalies_export.json")
    csv_data  = logger.read_from_csv("anomalies_export.csv")
    print(f"  JSON re-read: {len(json_data)} records, first IP = {json_data[0]['source_ip'] if json_data else 'n/a'}")
    print(f"  CSV  re-read: {len(csv_data)} records, first IP = {csv_data[0]['source_ip'] if csv_data else 'n/a'}")

    # ── WEEK 3 · STEP 8 — DB query summary ──────────────────────────────────
    print("\n--- Database query results ---")
    all_db_packets   = db.get_all_packets()
    open_anomalies   = db.get_open_anomalies()
    ddos_packets     = db.get_packets_by_label("ddos")
    suspicious_db    = db.get_packets_by_label("suspicious")
    print(f"  Total packets in DB    : {len(all_db_packets)}")
    print(f"  DDoS packets in DB     : {len(ddos_packets)}")
    print(f"  Suspicious packets     : {len(suspicious_db)}")
    print(f"  Open (unresolved) alerts: {len(open_anomalies)}")

    # ── WEEK 4 · STEP 9 — SQL aggregate stats ───────────────────────────────
    print("\n--- SQL Aggregate Statistics (Week 4) ---")
    try:
        stats = db.get_stats()
        print(f"  Devices tracked        : {stats['total_devices']}")
        print(f"  Total packets in DB    : {stats['total_packets']}")
        print(f"  Packets by label       : {stats['by_label']}")
        print(f"  Avg packets/sec        : {stats['avg_pps']}")
        print(f"  Total anomalies logged : {stats['total_anomalies']}")
        print(f"  Open alerts            : {stats['open_anomalies']}")
        print(f"  Alerts by severity     : {stats['by_severity']}")
    except DatabaseError as exc:
        logger.error(f"Stats query failed: {exc}")
        stats = {}

    # ── WEEK 4 · STEP 10 — Save final report to file ────────────────────────
    metrics = evaluator.evaluate(all_packets)
    _save_final_report(logger, stats, metrics, analyzer)

    logger.info("Week 4 run complete.")


def _save_final_report(logger, stats: dict, metrics: dict, analyzer) -> None:
    lines = [
        "=" * 55,
        "  AI NETWORK ANOMALY DETECTION — FINAL REPORT",
        "=" * 55,
        "",
        f"  Run date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "  [DATABASE STATS]",
        f"  Devices tracked      : {stats.get('total_devices', 'n/a')}",
        f"  Total packets in DB  : {stats.get('total_packets', 'n/a')}",
        f"  Packets by label     : {stats.get('by_label', {})}",
        f"  Avg packets/sec      : {stats.get('avg_pps', 'n/a')}",
        f"  Total anomaly alerts : {stats.get('total_anomalies', 'n/a')}",
        f"  Open (unresolved)    : {stats.get('open_anomalies', 'n/a')}",
        f"  Alerts by severity   : {stats.get('by_severity', {})}",
        "",
        "  [AI MODEL ACCURACY]",
        f"  Packets evaluated    : {metrics.get('total', 'n/a')}",
        f"  Correctly classified : {metrics.get('correct', 'n/a')}",
        f"  Overall accuracy     : {metrics.get('accuracy', 0) * 100:.1f}%",
        "",
        "  Per-class recall:",
    ]
    for label, s in metrics.get("per_class", {}).items():
        lines.append(f"    {label:12s}: {s['recall']:.0%}  ({s['correct']}/{s['total']})")

    lines += [
        "",
        "  [TRAFFIC ANALYSIS]",
        f"  Total bytes/s (all)  : {analyzer.total_bytes_transferred():,.0f}",
        f"  Total failed conns   : {analyzer.total_failed_connections()}",
        f"  Anomaly breakdown    : {analyzer.anomaly_summary()}",
        f"  Critical IPs (>=80)  : {analyzer.get_critical_ips(80.0)}",
        "",
        "=" * 55,
    ]
    report_text = "\n".join(lines)
    print("\n" + report_text)
    try:
        logger.export_to_json(
            [{"report": report_text, "metrics": metrics, "db_stats": stats}],
            "final_report.json",
        )
    except Exception as exc:
        logger.error(f"Could not save final report: {exc}")


if __name__ == "__main__":
    main()