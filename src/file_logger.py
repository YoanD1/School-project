import csv
import json
import os
from datetime import datetime
from typing import List

from src.exceptions import FileExportError


class FileLogger:
    def __init__(self, log_dir: str = "logs"):
        self._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._log_path = os.path.join(log_dir, "network_monitor.log")

    def log(self, level: str, message: str) -> None:
        entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{level.upper()}] {message}"
        print(entry)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except OSError as exc:
            raise FileExportError(f"Cannot write to log file: {exc}") from exc

    def info(self, message: str) -> None:
        self.log("INFO", message)

    def warning(self, message: str) -> None:
        self.log("WARNING", message)

    def error(self, message: str) -> None:
        self.log("ERROR", message)

    def export_to_json(self, data: List[dict], filename: str) -> None:
        path = os.path.join(self._log_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.info(f"Exported {len(data)} records to {path}")
        except (OSError, TypeError) as exc:
            raise FileExportError(f"JSON export failed: {exc}") from exc

    def export_to_csv(self, data: List[dict], filename: str) -> None:
        if not data:
            return
        path = os.path.join(self._log_dir, filename)
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            self.info(f"Exported {len(data)} records to {path}")
        except (OSError, csv.Error) as exc:
            raise FileExportError(f"CSV export failed: {exc}") from exc
