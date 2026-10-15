"""Local scan history. All SQL values are bound parameters."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3

from .models import HistoryEntry, HistorySummary, ScanOptions, ScanRun


def default_database_path() -> Path:
    state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return state / "nmap-edu-gui" / "history.db"


class HistoryError(ValueError):
    """Stored metadata cannot be interpreted."""


class HistoryDatabase:
    @staticmethod
    def _decode_command(value: str) -> list[str]:
        command = json.loads(value)
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            raise HistoryError("Invalid stored argv list.")
        return command

    @staticmethod
    def _decode_options(value: str) -> ScanOptions:
        data = json.loads(value)
        defaults = asdict(ScanOptions())
        if not isinstance(data, dict) or any(key not in defaults or type(val) is not type(defaults[key]) for key, val in data.items()):
            raise HistoryError("Invalid stored option types.")
        return ScanOptions(**data)

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else default_database_path()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        self._connection = sqlite3.connect(self.path, timeout=5)
        self._connection.row_factory = sqlite3.Row
        try:
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise HistoryError(f"History schema version {version} is newer than this application supports.")
            with self._connection:
                self._connection.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, target TEXT NOT NULL,
                    command TEXT NOT NULL, options TEXT NOT NULL,
                    duration REAL NOT NULL, result TEXT NOT NULL,
                    exit_code INTEGER, output TEXT NOT NULL, xml TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT ''
                )''')
                self._connection.execute("PRAGMA user_version = 1")
        except Exception:
            self._connection.close()
            raise

    def save_scan(self, timestamp: str, options: ScanOptions, run: ScanRun) -> int:
        result = "stopped" if run.stopped else ("completed" if run.exit_code == 0 and not run.error else "failed")
        with self._connection:
            cursor = self._connection.execute('''INSERT INTO scans
                (timestamp, target, command, options, duration, result, exit_code, output, xml, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (timestamp, options.target, json.dumps(run.command), json.dumps(asdict(options)),
                 run.elapsed, result, run.exit_code, run.output, run.xml, run.error))
        return cursor.lastrowid

    def list_scans(self, limit: int = 200) -> list[HistorySummary]:
        rows = self._connection.execute('''SELECT id, timestamp, target, command, duration, result, exit_code
            FROM scans ORDER BY id DESC LIMIT ?''', (limit,)).fetchall()
        try:
            return [HistorySummary(row["id"], row["timestamp"], row["target"], self._decode_command(row["command"]),
                row["duration"], row["result"], row["exit_code"]) for row in rows]
        except (ValueError, TypeError) as exc:
            raise HistoryError("History contains invalid command metadata.") from exc

    def get_scan(self, scan_id: int) -> HistoryEntry | None:
        row = self._connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        try:
            return HistoryEntry(row["id"], row["timestamp"], row["target"], self._decode_command(row["command"]),
                self._decode_options(row["options"]), row["duration"], row["result"],
                row["exit_code"], row["output"], row["xml"], row["error"])
        except (ValueError, TypeError) as exc:
            raise HistoryError("History contains invalid scan options.") from exc

    def close(self) -> None:
        self._connection.close()
