from dataclasses import replace
import stat

import pytest

from nmap_gui.database import HistoryDatabase
from nmap_gui.models import ScanOptions, ScanRun


def test_roundtrip_and_reopen(tmp_path):
    path = tmp_path / "state" / "history.db"
    database = HistoryDatabase(path)
    options = ScanOptions(target="127.0.0.1", service_detection=True, custom_ports="22", ports_mode="custom")
    run = ScanRun(["nmap", "-sT", "127.0.0.1"], "output with ' quotes", "<nmaprun/>", 0, 1.25)
    scan_id = database.save_scan("2026-10-15T10:00:00+00:00", options, run)
    database.close()
    database = HistoryDatabase(path)
    try:
        entry = database.get_scan(scan_id)
        assert entry.options == options
        assert entry.command == run.command
        assert entry.output == run.output
        assert entry.xml == run.xml
        assert entry.result == "completed"
        assert entry.duration == 1.25
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert database.get_scan(999) is None
        database.save_scan("later", options, replace(run, stopped=True))
        database.save_scan("latest", options, replace(run, exit_code=1))
        assert [r.result for r in database.list_scans()] == ["failed", "stopped", "completed"]
        assert len(database.list_scans(limit=1)) == 1
    finally:
        database.close()


def test_sql_values_are_bound(tmp_path):
    database = HistoryDatabase(tmp_path / "history.db")
    try:
        options = ScanOptions(target="'; DROP TABLE scans; --")
        database.save_scan("now", options, ScanRun(["nmap"], "", "", 1, 0))
        assert database.list_scans()[0].target == options.target
    finally:
        database.close()
