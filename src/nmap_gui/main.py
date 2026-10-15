"""Application entry point: python -m nmap_gui.main."""

import argparse
import sys

from PyQt6.QtWidgets import QApplication

from . import __version__
from .gui import MainWindow


def main() -> int:
    parser = argparse.ArgumentParser(description="Educational desktop interface for authorized Nmap testing")
    parser.add_argument("--version", action="version", version=f"Nmap Edu GUI {__version__}")
    parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("Nmap Edu GUI")
    app.setOrganizationName("NmapEduGUI")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
