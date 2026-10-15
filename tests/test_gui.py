import os
import sys

from nmap_gui.gui import MainWindow


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
