import os
import sys

from PyQt6.QtWidgets import QApplication

from nmap_gui.gui import MainWindow
from nmap_gui.models import ScanRun


def test_structured_results(qt_app):
    window = MainWindow()
    try:
        xml = '''<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames><hostname name="localhost"/></hostnames><ports><port protocol="tcp" portid="22">
        <state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port></ports></host></nmaprun>'''
        window._populate_results(ScanRun(["nmap"], "", xml, 0, 1.0))
        assert window.results_table.rowCount() == 1
        assert window.results_table.item(0, 5).text() == "ssh"
        assert window.results_table.item(0, 6).text() == "OpenSSH 9.2"
        assert window.hosts_table.item(0, 1).text() == "localhost"
        window._populate_results(ScanRun(["nmap"], "", "<broken", 1, 1.0))
        assert window.results_table.rowCount() == 0
        assert "Invalid or incomplete" in window.results_summary.text()
    finally:
        window.close()


def test_gui_streaming_and_stop(qt_app, wait_until, monkeypatch, tmp_path):
    """A local synthetic nmap process checks GUI/thread integration without probes."""
    executable = tmp_path / "nmap"
    executable.write_text(f"#!{sys.executable}\nimport time\nprint('stream ready', flush=True)\ntime.sleep(30)\n")
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    window = MainWindow()
    try:
        window.target.setText("127.0.0.1")
        window.start_scan()
        wait_until(lambda: "stream ready" in window.console.toPlainText())
        assert window._scanner is not None
        assert not window.run_button.isEnabled()
        assert window.stop_button.isEnabled()
        window.stop_scan()
        wait_until(lambda: window._scanner is None)
        assert window._last_run.stopped
        assert window.save_button.isEnabled()
        assert "Stopped" in window.statusBar().currentMessage()
    finally:
        if window._scanner is not None:
            window.stop_scan()
            wait_until(lambda: window._scanner is None)
        window.close()


def test_preview_validation_and_profile_switch(qt_app):
    window = MainWindow()
    try:
        assert not window.run_button.isEnabled()
        window.target.setText("127.0.0.1")
        assert "-sT" in window.command_preview.toPlainText()
        window.service_detection.setChecked(True)
        window.ports_mode.setCurrentIndex(window.ports_mode.findData("custom"))
        window.custom_ports.setText("22,80,443")
        assert "-sV" in window.command_preview.toPlainText()
        assert "-p 22,80,443" in window.command_preview.toPlainText()
        window.scan_type.setCurrentIndex(window.scan_type.findData("discovery"))
        assert "-sn" in window.command_preview.toPlainText()
        assert "-sV" not in window.command_preview.toPlainText()
        assert "-p " not in window.command_preview.toPlainText()
        assert not window.detection_group.isEnabled()
        window.target.setText("127.0.0.1;id")
        assert not window.run_button.isEnabled()
        assert not window.command_preview.toPlainText()
    finally:
        window.close()


def test_privilege_warning(qt_app, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    window = MainWindow()
    try:
        window.target.setText("127.0.0.1")
        window.scan_type.setCurrentIndex(window.scan_type.findData("syn"))
        assert "This scan requires elevated privileges" in window.privilege_label.text()
        assert not window.run_button.isEnabled()
        window.use_sudo.setChecked(True)
        assert window.command_preview.toPlainText().startswith("sudo -A -- nmap")
    finally:
        window.close()


def test_history_reopen_copy_and_rerun(qt_app, wait_until, tmp_path, monkeypatch):
    executable = tmp_path / "nmap"
    xml = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
    executable.write_text(f"#!{sys.executable}\nimport sys,pathlib\n"
        f"pathlib.Path(sys.argv[sys.argv.index('-oX')+1]).write_text({xml!r})\n"
        "print('synthetic completed scan', flush=True)\n")
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    database = tmp_path / "history.db"
    first = MainWindow(database)
    try:
        first.target.setText("127.0.0.1")
        first.timing.setCurrentIndex(4)
        first.start_scan()
        wait_until(lambda: first._scanner is None)
        assert first.history_table.rowCount() == 1
        previous_command = list(first._last_run.command)
    finally:
        first.close()
    second = MainWindow(database)
    try:
        second.history_table.selectRow(0)
        second.open_history()
        assert second.console.toPlainText() == "synthetic completed scan\n"
        assert second.hosts_table.item(0, 0).text() == "127.0.0.1"
        second.copy_history_command()
        assert "-T4" in QApplication.clipboard().text()
        assert previous_command[-2] in QApplication.clipboard().text()
        second.rerun_history()
        wait_until(lambda: second.history_table.rowCount() == 2 and second._scanner is None)
        assert second._last_run.exit_code == 0
        assert second._last_run.command != previous_command  # fresh private XML path
        assert second.selected_options().timing == 4
    finally:
        if second._scanner is not None:
            second.stop_scan()
            wait_until(lambda: second._scanner is None)
        second.close()


def test_history_failure_does_not_block_gui(qt_app, tmp_path):
    window = MainWindow(history_path=tmp_path)  # directory, not a database file
    try:
        assert "History unavailable" in window.history_status.text()
        window.target.setText("127.0.0.1")
        assert "nmap -sT" in window.command_preview.toPlainText()
    finally:
        window.close()


def test_missing_nmap_message(qt_app, monkeypatch):
    import nmap_gui.gui as gui
    original = gui.shutil.which
    monkeypatch.setattr(gui.shutil, "which", lambda name: None if name == "nmap" else original(name))
    window = MainWindow()
    try:
        assert "Nmap was not found" in window.privilege_label.text()
        window.target.setText("127.0.0.1")
        assert not window.run_button.isEnabled()
    finally:
        window.close()


def test_close_window_cancels_scan(qt_app, wait_until, tmp_path, monkeypatch):
    executable = tmp_path / "nmap"
    executable.write_text(f"#!{sys.executable}\nimport time\nprint('ready',flush=True)\ntime.sleep(30)\n")
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    window = MainWindow()
    window.show()
    window.target.setText("127.0.0.1")
    window.start_scan()
    try:
        wait_until(lambda: "ready" in window.console.toPlainText())
        window.close()
        wait_until(lambda: window._scanner is None and not window.isVisible())
        assert window._last_run.stopped
    finally:
        if window._scanner is not None:
            window.stop_scan()
            wait_until(lambda: window._scanner is None)
        window.close()
