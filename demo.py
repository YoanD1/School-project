"""
Interactive demo — run this to watch every part of the project in action.
Press Enter to move through each section.
"""
import csv
import os
from datetime import datetime

# ── helpers ──────────────────────────────────────────────────────────────────

def section(title):
    input(f"\n{'='*55}\n  {title}\n{'='*55}\n  (press Enter to run this section...)")

def show(label, value):
    print(f"  {label}: {value}")

# ── imports ───────────────────────────────────────────────────────────────────

from src.network_packet import NetworkPacket
from src.anomaly_detector import AnomalyDetector
from src.traffic_analyzer import TrafficAnalyzer
from src.event_manager import EventManager, AnomalyEventArgs, DDoSEventArgs, UnusualTrafficEventArgs
from src.database_service import DatabaseService
from src.file_logger import FileLogger
from src.monitoring_service import MonitoringService
from src.traffic_simulator import TrafficSimulator
from src.exceptions import InsufficientTrainingDataError, DetectionError, DatabaseError

# ── clean slate ───────────────────────────────────────────────────────────────

DB_PATH = "db/demo.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

logger = FileLogger("logs")
db = DatabaseService(DB_PATH)
events = EventManager()
detector = AnomalyDetector()
analyzer = TrafficAnalyzer()
service = MonitoringService(detector, analyzer, events, db, logger)
simulator = TrafficSimulator()


# ══════════════════════════════════════════════════════════════════════════════
# 1. NetworkPacket — the data model
# ══════════════════════════════════════════════════════════════════════════════
section("1. NetworkPacket — creating and inspecting packets")

normal_pkt = NetworkPacket(
    source_ip="192.168.1.10", dest_ip="10.0.0.1",
    protocol="HTTP", port=80, packet_size=512,
    packets_per_second=15, bytes_per_second=7680,
    failed_connections=0, timestamp=datetime.now(), label="normal",
)
ddos_pkt = NetworkPacket(
    source_ip="45.33.32.156", dest_ip="192.168.1.10",
    protocol="TCP", port=0, packet_size=64,
    packets_per_second=950, bytes_per_second=60800,
    failed_connections=0, timestamp=datetime.now(), label="ddos",
)

print("  Normal packet:")
show("    str()", str(normal_pkt))
show("    to_dict() keys", list(normal_pkt.to_dict().keys()))

print("\n  DDoS packet:")
show("    str()", str(ddos_pkt))

# Reconstruct from dict (round-trip)
reconstructed = NetworkPacket.from_dict(normal_pkt.to_dict())
show("\n  from_dict() round-trip matches", reconstructed.source_ip == normal_pkt.source_ip)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Custom exceptions — testing error cases
# ══════════════════════════════════════════════════════════════════════════════
section("2. Custom Exceptions")

print("  Predicting without training first (should raise InsufficientTrainingDataError):")
try:
    fresh = AnomalyDetector()
    fresh.train([])  # no data — should raise
except InsufficientTrainingDataError as e:
    show("    Caught InsufficientTrainingDataError", e)

print("\n  Connecting to a bad DB path (should raise DatabaseError):")
try:
    DatabaseService("Z:/nonexistent/path/db.db")
except DatabaseError as e:
    show("    Caught DatabaseError", e)


# ══════════════════════════════════════════════════════════════════════════════
# 3. AnomalyDetector — training and prediction
# ══════════════════════════════════════════════════════════════════════════════
section("3. AnomalyDetector — train on CSV, then predict")

packets_csv = []
with open("data/sample_traffic.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        packets_csv.append(NetworkPacket(
            id=int(row["id"]), source_ip=row["source_ip"], dest_ip=row["dest_ip"],
            protocol=row["protocol"], port=int(row["port"]),
            packet_size=int(row["packet_size"]),
            packets_per_second=float(row["packets_per_second"]),
            bytes_per_second=float(row["bytes_per_second"]),
            failed_connections=int(row["failed_connections"]),
            timestamp=datetime.fromisoformat(row["timestamp"]), label=row["label"],
        ))

normal_only = [p for p in packets_csv if p.label == "normal"]
detector.train(normal_only)
show("  Trained on N normal packets", len(normal_only))
show("  is_trained", detector.is_trained)

test_cases = [
    ("Normal HTTP packet",   normal_pkt),
    ("DDoS packet (950 pps)", ddos_pkt),
    (
        "Port scan (50 failed connections)",
        NetworkPacket("203.0.113.50","192.168.1.5","TCP",22,60,110,6600,50,datetime.now()),
    ),
]
print()
for name, pkt in test_cases:
    label, conf = detector.predict(pkt)
    show(f"  {name}", f"label={label}  confidence={conf}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. EventManager — Observer pattern with 2 listeners per event
# ══════════════════════════════════════════════════════════════════════════════
section("4. EventManager — Observer pattern (2 listeners per event)")

fired_log = []  # collects every callback that fires

def listener_a_anomaly(args: AnomalyEventArgs):
    msg = f"[Listener A] anomaly: {args.anomaly_type} from {args.source_ip}"
    fired_log.append(msg); print("  " + msg)

def listener_b_anomaly(args: AnomalyEventArgs):
    msg = f"[Listener B] severity={args.severity} packet_id={args.packet_id}"
    fired_log.append(msg); print("  " + msg)

def listener_a_ddos(args: DDoSEventArgs):
    msg = f"[Listener A] DDoS: {args.attacker_ip} -> {args.target_ip} ({args.packets_per_second:.0f} pps)"
    fired_log.append(msg); print("  " + msg)

def listener_b_ddos(args: DDoSEventArgs):
    msg = f"[Listener B] DDoS alert logged to security team"
    fired_log.append(msg); print("  " + msg)

def listener_a_unusual(args: UnusualTrafficEventArgs):
    msg = f"[Listener A] unusual: {args.description} device={args.device_ip}"
    fired_log.append(msg); print("  " + msg)

def listener_b_unusual(args: UnusualTrafficEventArgs):
    msg = f"[Listener B] protocol={args.protocol} flagged for review"
    fired_log.append(msg); print("  " + msg)

demo_events = EventManager()
demo_events.subscribe(EventManager.ON_ANOMALY_DETECTED, listener_a_anomaly)
demo_events.subscribe(EventManager.ON_ANOMALY_DETECTED, listener_b_anomaly)
demo_events.subscribe(EventManager.ON_DDOS_SUSPECTED,   listener_a_ddos)
demo_events.subscribe(EventManager.ON_DDOS_SUSPECTED,   listener_b_ddos)
demo_events.subscribe(EventManager.ON_UNUSUAL_TRAFFIC,  listener_a_unusual)
demo_events.subscribe(EventManager.ON_UNUSUAL_TRAFFIC,  listener_b_unusual)

print("  Dispatching ON_ANOMALY_DETECTED:")
demo_events.dispatch(EventManager.ON_ANOMALY_DETECTED,
    AnomalyEventArgs(packet_id=99, anomaly_type="suspicious", severity="high", source_ip="203.0.113.50"))

print("\n  Dispatching ON_DDOS_SUSPECTED:")
demo_events.dispatch(EventManager.ON_DDOS_SUSPECTED,
    DDoSEventArgs(attacker_ip="45.33.32.156", target_ip="192.168.1.10", packets_per_second=950))

print("\n  Dispatching ON_UNUSUAL_TRAFFIC:")
demo_events.dispatch(EventManager.ON_UNUSUAL_TRAFFIC,
    UnusualTrafficEventArgs(description="High bandwidth", device_ip="10.10.10.5", protocol="ICMP"))

show("\n  Total callbacks fired", len(fired_log))


# ══════════════════════════════════════════════════════════════════════════════
# 5. DatabaseService — CRUD operations
# ══════════════════════════════════════════════════════════════════════════════
section("5. DatabaseService — CRUD on all 3 tables")

# devices
dev_id = db.upsert_device("192.168.1.99", mac="AA:BB:CC:DD:EE:FF", name="TestPC", device_type="workstation")
show("  upsert_device() -> id", dev_id)

# calling again should update last_seen, not create duplicate
same_id = db.upsert_device("192.168.1.99")
show("  upsert again (same IP) -> same id?", dev_id == same_id)

# packets
normal_pkt.device_id = dev_id
pkt_id = db.insert_packet(normal_pkt)
show("  insert_packet() -> id", pkt_id)

rows = db.get_packets_by_label("normal")
show("  get_packets_by_label('normal') count", len(rows))

# anomalies
anom_id = db.insert_anomaly(pkt_id, "suspicious", "medium", "Demo anomaly")
show("  insert_anomaly() -> id", anom_id)

open_a = db.get_open_anomalies()
show("  get_open_anomalies() count", len(open_a))

db.resolve_anomaly(anom_id)
open_after = db.get_open_anomalies()
show("  after resolve_anomaly() open count", len(open_after))


# ══════════════════════════════════════════════════════════════════════════════
# 6. TrafficAnalyzer — LINQ-style operations
# ══════════════════════════════════════════════════════════════════════════════
section("6. TrafficAnalyzer — LINQ-style queries")

for p in packets_csv:
    analyzer.add_packet(p)

show("  anomaly_summary()",         analyzer.anomaly_summary())
show("  get_top_source_ips(3)",     analyzer.get_top_source_ips(3))
show("  high traffic count",        len(analyzer.get_high_traffic_packets(100)))
show("  avg packet size (bytes)",   round(analyzer.average_packet_size(), 1))

groups = analyzer.get_packets_by_protocol()
show("  packets by protocol",       {k: len(v) for k, v in groups.items()})

suspicious = analyzer.get_suspicious_packets()
show("  suspicious IPs (sample)",   [p.source_ip for p in suspicious[:3]])


# ══════════════════════════════════════════════════════════════════════════════
# 7. TrafficSimulator — live packet generation
# ══════════════════════════════════════════════════════════════════════════════
section("7. TrafficSimulator — generate synthetic packets")

print("  3 normal packets:")
for p in [simulator.generate_normal() for _ in range(3)]:
    show("   ", str(p))

print("\n  2 DDoS packets:")
for p in [simulator.generate_ddos() for _ in range(2)]:
    show("   ", str(p))

print("\n  2 port-scan packets:")
for p in [simulator.generate_port_scan() for _ in range(2)]:
    show("   ", str(p))

batch = simulator.generate_batch(total=10, anomaly_ratio=0.4)
show("\n  generate_batch(10, 0.4) label breakdown",
     {l: sum(1 for p in batch if p.label == l) for l in set(p.label for p in batch)})


# ══════════════════════════════════════════════════════════════════════════════
# 8. MonitoringService — full pipeline end-to-end
# ══════════════════════════════════════════════════════════════════════════════
section("8. MonitoringService — full pipeline on a live batch")

live_batch = simulator.generate_batch(total=8, anomaly_ratio=0.5)
print(f"  Processing {len(live_batch)} packets through the full pipeline:\n")
service.process_batch(live_batch)
service.print_summary()


# ══════════════════════════════════════════════════════════════════════════════
# 9. FileLogger — export to JSON and CSV
# ══════════════════════════════════════════════════════════════════════════════
section("9. FileLogger — export anomalies to JSON and CSV")

all_suspicious = analyzer.get_suspicious_packets()
logger.export_to_json([p.to_dict() for p in all_suspicious], "demo_anomalies.json")
logger.export_to_csv([p.to_dict() for p in all_suspicious],  "demo_anomalies.csv")
show("  Files written to logs/", ["demo_anomalies.json", "demo_anomalies.csv"])


# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*55)
print("  All sections complete. Check logs/ for exported files.")
print("="*55 + "\n")
