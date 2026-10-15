"""Render actual Qt widgets using clearly labelled sample data; sends no probes.

Run from the repository root with QT_QPA_PLATFORM=offscreen if headless.
"""

from datetime import datetime, timezone
from pathlib import Path
import shlex
import tempfile

from PyQt6.QtWidgets import QApplication

from nmap_gui.command_builder import NmapCommandBuilder
from nmap_gui.gui import MainWindow
from nmap_gui.models import ScanOptions, ScanRun


def main():
    root = Path(__file__).resolve().parents[1]
    app = QApplication([])
    app.setStyle("Fusion")
    with tempfile.TemporaryDirectory(prefix="nmap-gui-screenshot-") as directory:
        window = MainWindow(Path(directory) / "history.db")
        window.setWindowTitle("Nmap Edu GUI — illustrative sample data")
        options = ScanOptions(target="192.168.56.101", ports_mode="custom", custom_ports="22,80,443", service_detection=True)
        window.restore_options(options)
        # Keep a stable illustrative temp path in the documentation image.
        window.command_preview.setPlainText(NmapCommandBuilder(options).preview("/tmp/nmap-gui-example/scan.xml"))
        xml = (root / "tests/fixtures/lab.xml").read_text(encoding="utf-8")
        run = ScanRun(NmapCommandBuilder(options).build(),
            "ILLUSTRATIVE SAMPLE — no scan was performed to create this screenshot.\n\n"
            "Nmap scan report for lab-vm.local (192.168.56.101)\nHost is up.\n\n"
            "PORT    STATE   SERVICE VERSION\n"
            "22/tcp  open    ssh     OpenSSH 9.2p1\n"
            "80/tcp  open    http    Apache httpd 2.4.62\n"
            "443/tcp closed  https\n\nNmap done: 1 IP address (1 host up) scanned.\n", xml, 0, 1.0)
        window._last_run = run
        window.console.setPlainText(run.output)
        window._populate_results(run)
        window.results_summary.setText("ILLUSTRATIVE SAMPLE DATA · " + window.results_summary.text())
        window._history.save_scan(datetime.now(timezone.utc).isoformat(timespec="seconds"), options, run)
        window.refresh_history()
        window.save_button.setEnabled(True)
        window.statusBar().showMessage("Documentation preview — sample lab data; no network probes sent.")
        window.show()
        destination = root / "screenshots"
        destination.mkdir(exist_ok=True)
        for tab, filename in ((1, "main-window.png"), (0, "output.png"), (2, "discovered-hosts.png")):
            window.tabs.setCurrentIndex(tab)
            app.processEvents()
            if not window.grab().save(str(destination / filename)):
                raise RuntimeError(f"Could not save {filename}")
        window.close()


if __name__ == "__main__":
    main()
