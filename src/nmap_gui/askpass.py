"""Separate, unprivileged graphical password prompt called directly by sudo.

The password travels only over sudo's askpass pipe. The main application never
receives it. No password is saved in files, settings, logs or scan history.
"""

import sys

from PyQt6.QtWidgets import QApplication, QInputDialog, QLineEdit


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("Nmap Edu GUI — sudo authentication")
    password, accepted = QInputDialog.getText(
        None, "Authorize Nmap with sudo",
        "Authenticate to run the selected Nmap scan with elevated privileges.\n"
        "Password (sent directly to sudo; never saved):",
        QLineEdit.EchoMode.Password,
    )
    if not accepted:
        return 1
    sys.stdout.write(password + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
