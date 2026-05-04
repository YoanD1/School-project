import sqlite3
from datetime import datetime
from typing import List

from src.network_packet import NetworkPacket
from src.exceptions import DatabaseError


class DatabaseService:
    def __init__(self, db_path: str = "db/network_monitor.db"):
        self._db_path = db_path
        try:
            self._init_schema()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to initialise database at {db_path}: {exc}") from exc

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address  TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    is_trusted  INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS packets (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip           TEXT NOT NULL,
                    dest_ip             TEXT NOT NULL,
                    protocol            TEXT NOT NULL,
                    port                INTEGER NOT NULL,
                    packet_size         INTEGER NOT NULL,
                    packets_per_second  REAL NOT NULL,
                    bytes_per_second    REAL NOT NULL,
                    failed_connections  INTEGER NOT NULL,
                    timestamp           TEXT NOT NULL,
                    label               TEXT NOT NULL DEFAULT 'normal',
                    device_id           INTEGER,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                );

                CREATE TABLE IF NOT EXISTS anomalies (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_id    INTEGER NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    description  TEXT,
                    detected_at  TEXT NOT NULL,
                    is_resolved  INTEGER DEFAULT 0,
                    FOREIGN KEY (packet_id) REFERENCES packets(id)
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    # --- packets CRUD ---

    def insert_packet(self, packet: NetworkPacket) -> int:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """INSERT INTO packets
                       (source_ip, dest_ip, protocol, port, packet_size,
                        packets_per_second, bytes_per_second, failed_connections,
                        timestamp, label, device_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        packet.source_ip, packet.dest_ip, packet.protocol,
                        packet.port, packet.packet_size, packet.packets_per_second,
                        packet.bytes_per_second, packet.failed_connections,
                        packet.timestamp.isoformat(), packet.label, packet.device_id,
                    ),
                )
                return cur.lastrowid
        except sqlite3.Error as exc:
            raise DatabaseError(f"insert_packet failed: {exc}") from exc

    def get_all_packets(self) -> List[dict]:
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                return [dict(r) for r in conn.execute("SELECT * FROM packets").fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"get_all_packets failed: {exc}") from exc

    def get_packets_by_label(self, label: str) -> List[dict]:
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                return [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM packets WHERE label = ?", (label,)
                    ).fetchall()
                ]
        except sqlite3.Error as exc:
            raise DatabaseError(f"get_packets_by_label failed: {exc}") from exc

    # --- anomalies CRUD ---

    def insert_anomaly(
        self,
        packet_id: int,
        anomaly_type: str,
        severity: str,
        description: str = "",
    ) -> int:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """INSERT INTO anomalies
                       (packet_id, anomaly_type, severity, description, detected_at)
                       VALUES (?,?,?,?,?)""",
                    (packet_id, anomaly_type, severity, description, datetime.now().isoformat()),
                )
                return cur.lastrowid
        except sqlite3.Error as exc:
            raise DatabaseError(f"insert_anomaly failed: {exc}") from exc

    def resolve_anomaly(self, anomaly_id: int) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE anomalies SET is_resolved = 1 WHERE id = ?", (anomaly_id,)
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"resolve_anomaly failed: {exc}") from exc

    def get_open_anomalies(self) -> List[dict]:
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                return [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM anomalies WHERE is_resolved = 0"
                    ).fetchall()
                ]
        except sqlite3.Error as exc:
            raise DatabaseError(f"get_open_anomalies failed: {exc}") from exc

    # --- devices CRUD ---

    def upsert_device(self, ip: str, mac: str = "", name: str = "", device_type: str = "") -> int:
        try:
            now = datetime.now().isoformat()
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT id FROM devices WHERE ip_address = ?", (ip,)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE devices SET last_seen = ? WHERE ip_address = ?", (now, ip)
                    )
                    return existing[0]
                cur = conn.execute(
                    """INSERT INTO devices
                       (ip_address, mac_address, device_name, device_type, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?)""",
                    (ip, mac, name, device_type, now, now),
                )
                return cur.lastrowid
        except sqlite3.Error as exc:
            raise DatabaseError(f"upsert_device failed for {ip}: {exc}") from exc
