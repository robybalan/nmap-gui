"""Qt presentation layer. Scan execution, validation and argv live elsewhere."""

from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import tempfile
import time

from PyQt6.QtCore import Qt, QTimer, QSignalBlocker
from PyQt6.QtGui import QFontDatabase, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QSpinBox, QSplitter, QTabWidget, QVBoxLayout, QWidget,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)

from .command_builder import NmapCommandBuilder
from .database import HistoryDatabase, HistoryError
from .models import ScanOptions, ScanRun
from .parser import NmapXmlError, NmapXmlParser
from .scanner import NmapScanner, find_askpass
from .validators import ValidationError

SCAN_CHOICES = [
    ("TCP Connect Scan · -sT", "connect", "Uses ordinary TCP connections; suitable without root privileges."),
    ("Ping Scan · -sn", "discovery", "Host discovery only. Does not scan ports."),
    ("SYN Scan · -sS", "syn", "Sends raw SYN probes; requires elevated privileges."),
    ("UDP Scan · -sU", "udp", "Probes UDP services. Can be slow; requires elevated privileges."),
    ("ACK Scan · -sA", "ack", "Maps filtering behavior; does not identify open ports. Requires elevated privileges."),
]
DISCOVERY_CHOICES = [
    ("Default Nmap discovery", "default", "Uses Nmap's normal discovery probes; may use ARP on a local network."),
    ("Skip host discovery · -Pn", "skip", "Assumes the target is up. Not compatible with Ping Scan."),
    ("TCP SYN discovery · -PS", "syn", "Discovers hosts using TCP SYN probes; connect fallback is possible without root."),
    ("TCP ACK discovery · -PA", "ack", "Discovers hosts using TCP ACK probes; this GUI requests privileges."),
    ("UDP discovery · -PU", "udp", "Discovers hosts using UDP probes; requires elevated privileges."),
]
PORT_CHOICES = [
    ("Default Nmap ports", "default"), ("Top 10 ports", "top10"),
    ("Top 100 ports", "top100"), ("Top 1000 ports", "top1000"),
    ("All ports · -p-", "all"), ("Custom ports", "custom"),
]
TIMING_CHOICES = ["T0 · Paranoid", "T1 · Sneaky", "T2 · Polite", "T3 · Normal", "T4 · Aggressive", "T5 · Insane"]


class MainWindow(QMainWindow):
    def __init__(self, history_path: str | Path | None = None):
        super().__init__()
        self.setWindowTitle("Nmap Edu GUI")
        self.resize(1220, 850)
        self._temporary = tempfile.TemporaryDirectory(prefix="nmap-gui-")
        self._xml_path = str(Path(self._temporary.name) / "scan.xml")
        self._scanner: NmapScanner | None = None
        self._last_run: ScanRun | None = None
        self._active_options: ScanOptions | None = None
        self._close_requested = False
        self._started = 0.0
        self._timestamp = ""
        self._history: HistoryDatabase | None = None
        history_error = ""
        try:
            self._history = HistoryDatabase(history_path)
        except (OSError, sqlite3.Error, HistoryError) as exc:
            history_error = f"History unavailable: {exc}"
        self._build_ui()
        self._connect_controls()
        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._update_elapsed)
        self.update_preview()
        self.refresh_history()
        if history_error:
            self.history_status.setText(history_error)

    @staticmethod
    def _combo(choices) -> QComboBox:
        combo = QComboBox()
        for choice in choices:
            combo.addItem(choice[0], choice[1])
            if len(choice) == 3:
                combo.setItemData(combo.count() - 1, choice[2], Qt.ItemDataRole.ToolTipRole)
        return combo

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 16, 20, 16)
        title = QLabel("Nmap Edu GUI")
        title.setObjectName("title")
        layout.addWidget(title)
        note = QLabel("Discovery, enumeration and service identification for authorized labs, CTFs and personal networks.")
        note.setWordWrap(True)
        layout.addWidget(note)
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target IP / Host / Subnet"))
        self.target = QLineEdit()
        self.target.setPlaceholderText("192.168.56.101  ·  192.168.56.0/24  ·  scanme.nmap.org  ·  ::1")
        self.target.setClearButtonEnabled(True)
        self.target.setObjectName("target")
        target_row.addWidget(self.target, 1)
        self.ipv6 = QCheckBox("IPv6 DNS · -6")
        self.ipv6.setToolTip("IPv6 literals and CIDRs select -6 automatically. Enable this for IPv6 hostname resolution.")
        target_row.addWidget(self.ipv6)
        layout.addLayout(target_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, 1)
        self.options_panel = QWidget()
        option_layout = QVBoxLayout(self.options_panel)
        option_layout.setContentsMargins(0, 0, 10, 0)

        profile_group = QGroupBox("Scan Profiles")
        form = QFormLayout(profile_group)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        profile_buttons = QHBoxLayout()
        host_profile = QPushButton("Host Discovery")
        port_profile = QPushButton("Port Scan")
        host_profile.setToolTip("Select Ping Scan (-sn): discover hosts without scanning ports.")
        port_profile.setToolTip("Select TCP Connect (-sT), then choose a port scanning technique below.")
        host_profile.clicked.connect(lambda: self.scan_type.setCurrentIndex(self.scan_type.findData("discovery")))
        port_profile.clicked.connect(lambda: self.scan_type.setCurrentIndex(self.scan_type.findData("connect")))
        profile_buttons.addWidget(host_profile)
        profile_buttons.addWidget(port_profile)
        form.addRow(profile_buttons)
        self.scan_type = self._combo(SCAN_CHOICES)
        form.addRow("Scan", self.scan_type)
        self.discovery = self._combo(DISCOVERY_CHOICES)
        form.addRow("Host Discovery", self.discovery)
        self.profile_help = QLabel()
        self.profile_help.setWordWrap(True)
        form.addRow(self.profile_help)
        option_layout.addWidget(profile_group)

        ports_group = QGroupBox("Port Scan")
        form = QFormLayout(ports_group)
        self.ports_mode = self._combo(PORT_CHOICES)
        form.addRow("Ports", self.ports_mode)
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("22,80,443,8000-9000")
        form.addRow("Custom ports", self.custom_ports)
        option_layout.addWidget(ports_group)

        detection_group = QGroupBox("Detection & Scripts")
        form = QFormLayout(detection_group)
        self.service_detection = QCheckBox("Service Version Detection · -sV")
        self.service_detection.setToolTip("Probes services to identify products and versions.")
        form.addRow(self.service_detection)
        self.intensity = QSpinBox()
        self.intensity.setRange(0, 9)
        self.intensity.setValue(7)
        self.intensity.setToolTip("Version detection intensity: 0 is lightest, 9 tries all probes; Nmap default is 7.")
        form.addRow("Version intensity", self.intensity)
        self.os_detection = QCheckBox("Operating System Detection · -O")
        self.os_detection.setToolTip("Uses raw packet fingerprints; requires elevated privileges.")
        form.addRow(self.os_detection)
        self.default_scripts = QCheckBox("Default NSE Scripts · -sC")
        self.default_scripts.setToolTip("Runs Nmap's default NSE scripts. Some scripts may be intrusive; use only with authorization.")
        form.addRow(self.default_scripts)
        self.aggressive = QCheckBox("Aggressive Scan · -A")
        self.aggressive.setToolTip("Enables OS detection, version detection, default script scanning and traceroute.")
        form.addRow(self.aggressive)
        self.detection_group = detection_group
        option_layout.addWidget(detection_group)

        tuning_group = QGroupBox("Timing & Output")
        form = QFormLayout(tuning_group)
        self.timing = QComboBox()
        self.timing.addItems(TIMING_CHOICES)
        self.timing.setCurrentIndex(3)
        self.timing.setToolTip("T0/T1 are very slow; T2 reduces load; T3 is the default; T4/T5 trade patience for speed.")
        form.addRow("Timing", self.timing)
        self.verbosity = QComboBox()
        self.verbosity.addItems(["Normal", "Verbose · -v", "Very Verbose · -vv"])
        form.addRow("Verbosity", self.verbosity)
        self.use_sudo = QCheckBox("Use sudo for this scan")
        self.use_sudo.setToolTip("Runs only Nmap via sudo -A. A separate helper prompts if required; passwords are never saved.")
        form.addRow(self.use_sudo)
        option_layout.addWidget(tuning_group)
        option_layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.options_panel)
        scroll.setMinimumWidth(370)
        splitter.addWidget(scroll)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 0, 0, 0)
        command_group = QGroupBox("Generated Command")
        command_layout = QVBoxLayout(command_group)
        monospace = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.command_preview = QPlainTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setFont(monospace)
        self.command_preview.setMaximumHeight(105)
        command_layout.addWidget(self.command_preview)
        command_note = QLabel("Exact argv shown before execution. -oX stores structured results in a private temporary file.")
        command_note.setWordWrap(True)
        command_layout.addWidget(command_note)
        right_layout.addWidget(command_group)
        self.validation_label = QLabel()
        self.validation_label.setWordWrap(True)
        self.validation_label.setTextFormat(Qt.TextFormat.PlainText)
        right_layout.addWidget(self.validation_label)
        self.privilege_label = QLabel()
        self.privilege_label.setWordWrap(True)
        right_layout.addWidget(self.privilege_label)

        buttons = QHBoxLayout()
        self.run_button = QPushButton("Run Scan")
        self.run_button.setObjectName("run")
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("Clear")
        self.save_button = QPushButton("Save Results")
        self.save_button.setEnabled(False)
        self.copy_command_button = QPushButton("Copy Command")
        for button in (self.run_button, self.stop_button, self.clear_button, self.save_button, self.copy_command_button):
            buttons.addWidget(button)
        right_layout.addLayout(buttons)
        self.tabs = QTabWidget()
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setFont(monospace)
        self.console.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        output_layout.addWidget(self.console)
        copy_output = QPushButton("Copy Output")
        copy_output.clicked.connect(lambda: QApplication.clipboard().setText(self.console.toPlainText()))
        output_layout.addWidget(copy_output, alignment=Qt.AlignmentFlag.AlignRight)
        self.tabs.addTab(output_panel, "Output")
        result_panel = QWidget()
        result_layout = QVBoxLayout(result_panel)
        self.results_summary = QLabel("Run a scan to see structured results.")
        self.results_summary.setWordWrap(True)
        result_layout.addWidget(self.results_summary)
        self.results_table = self._table(["Host", "Status", "Port", "Protocol", "State", "Service", "Version"])
        result_layout.addWidget(self.results_table)
        self.tabs.addTab(result_panel, "Results")
        self.hosts_table = self._table(["IP Address", "Hostname", "Status", "MAC Address", "Vendor"])
        self.tabs.addTab(self.hosts_table, "Discovered Hosts")
        history_panel = QWidget()
        history_layout = QVBoxLayout(history_panel)
        self.history_status = QLabel("Most recent 200 scans. Output and XML are stored locally.")
        self.history_status.setWordWrap(True)
        history_layout.addWidget(self.history_status)
        self.history_table = self._table(["Timestamp (UTC)", "Target", "Duration", "Result", "Exit code", "Command"])
        history_layout.addWidget(self.history_table)
        history_buttons = QHBoxLayout()
        self.open_history_button = QPushButton("Open Results")
        self.copy_history_button = QPushButton("Copy Command")
        self.rerun_history_button = QPushButton("Rerun Scan")
        refresh_button = QPushButton("Refresh")
        self.open_history_button.clicked.connect(self.open_history)
        self.copy_history_button.clicked.connect(self.copy_history_command)
        self.rerun_history_button.clicked.connect(self.rerun_history)
        refresh_button.clicked.connect(self.refresh_history)
        self.history_table.itemSelectionChanged.connect(self._update_history_buttons)
        self.history_table.itemDoubleClicked.connect(self.open_history)
        for button in (self.open_history_button, self.copy_history_button, self.rerun_history_button, refresh_button):
            history_buttons.addWidget(button)
        history_layout.addLayout(history_buttons)
        self.tabs.addTab(history_panel, "History")
        right_layout.addWidget(self.tabs, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([390, 790])
        self.setStyleSheet("""
            QMainWindow { background: #f3f6f8; }
            QLabel#title { color: #145e65; font-size: 25px; font-weight: 700; }
            QGroupBox { font-weight: 600; border: 1px solid #c6d3db; border-radius: 7px;
                        margin-top: 12px; padding: 12px 8px 8px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QPushButton { padding: 7px 10px; }
            QPushButton#run { background: #16737c; color: white; border-radius: 5px; }
            QPushButton#run:disabled { background: #9aabb2; }
            QPlainTextEdit#console { background: #18222d; color: #dce7ee; border: 0; padding: 8px; }
        """)
        self.statusBar().showMessage("Ready — enter an authorized target.")

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    @staticmethod
    def _fill_table(table: QTableWidget, rows: list[list[str]]) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                table.setItem(row, column, item)
        table.setSortingEnabled(True)

    def _connect_controls(self) -> None:
        self.target.textChanged.connect(self.update_preview)
        self.custom_ports.textChanged.connect(self.update_preview)
        for combo in (self.scan_type, self.discovery, self.ports_mode, self.timing, self.verbosity):
            combo.currentIndexChanged.connect(self.update_preview)
        for checkbox in (self.service_detection, self.os_detection, self.default_scripts, self.aggressive, self.use_sudo, self.ipv6):
            checkbox.toggled.connect(self.update_preview)
        self.intensity.valueChanged.connect(self.update_preview)
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.clear_button.clicked.connect(self.console.clear)
        self.copy_command_button.clicked.connect(self.copy_command)
        self.save_button.clicked.connect(self.save_results)

    def selected_options(self) -> ScanOptions:
        ping = self.scan_type.currentData() == "discovery"
        discovery = self.discovery.currentData()
        return ScanOptions(
            target=self.target.text(), scan_type=self.scan_type.currentData(),
            discovery="default" if ping and discovery == "skip" else discovery,
            ports_mode="default" if ping else self.ports_mode.currentData(),
            custom_ports=self.custom_ports.text(), service_detection=not ping and self.service_detection.isChecked(),
            version_intensity=self.intensity.value(), os_detection=not ping and self.os_detection.isChecked(),
            default_scripts=not ping and self.default_scripts.isChecked(), aggressive=not ping and self.aggressive.isChecked(),
            timing=self.timing.currentIndex(), verbosity=self.verbosity.currentIndex(),
            use_sudo=self.use_sudo.isChecked(), ipv6=self.ipv6.isChecked(),
        )

    def update_preview(self, *_args) -> None:
        if self._scanner is not None:
            return
        ping = self.scan_type.currentData() == "discovery"
        if ping and self.discovery.currentData() == "skip":
            self.discovery.setCurrentIndex(0)
        self.discovery.model().item(1).setEnabled(not ping)
        self.ports_mode.setEnabled(not ping)
        self.custom_ports.setEnabled(not ping and self.ports_mode.currentData() == "custom")
        self.detection_group.setEnabled(not ping)
        aggressive = self.aggressive.isChecked()
        for checkbox in (self.service_detection, self.os_detection, self.default_scripts):
            checkbox.setEnabled(not aggressive)
        self.intensity.setEnabled(aggressive or self.service_detection.isChecked())
        self.profile_help.setText(self.scan_type.currentData(Qt.ItemDataRole.ToolTipRole))
        try:
            builder = NmapCommandBuilder(self.selected_options())
            self.command_preview.setPlainText(builder.preview(self._xml_path))
            self.validation_label.setText("")
            problem = self._execution_problem(builder)
            self.privilege_label.setText(problem or (
                "Only Nmap will use sudo. A separate authentication dialog may appear."
                if builder.options.use_sudo else "This selection can run without elevating the application."
            ))
            self.run_button.setEnabled(not problem)
            self.copy_command_button.setEnabled(True)
        except ValidationError as exc:
            self.command_preview.clear()
            self.validation_label.setText(str(exc))
            self.privilege_label.setText("Nmap was not found. Install it with: sudo apt install nmap, then restart the app."
                                         if not shutil.which("nmap") else "")
            self.run_button.setEnabled(False)
            self.copy_command_button.setEnabled(False)

    @staticmethod
    def _execution_problem(builder: NmapCommandBuilder) -> str:
        if not shutil.which("nmap"):
            return "Nmap was not found. Install it with: sudo apt install nmap, then restart the app."
        if builder.options.use_sudo and not shutil.which("sudo"):
            return "sudo was not found. Install sudo or choose an unprivileged scan."
        if builder.options.use_sudo and not find_askpass():
            return "sudo helper not found. Install the project using pip install -r requirements.txt."
        if builder.requires_elevation and os.geteuid() != 0 and not builder.options.use_sudo:
            return "This scan requires elevated privileges. Select 'Use sudo for this scan'."
        return ""

    def copy_command(self) -> None:
        QApplication.clipboard().setText(self.command_preview.toPlainText())

    def append_output(self, text: str) -> None:
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self.console.setTextCursor(cursor)
        self.console.ensureCursorVisible()

    def start_scan(self) -> None:
        if self._scanner is not None:
            return
        try:
            options = self.selected_options()
            builder = NmapCommandBuilder(options)
            command = builder.build(self._xml_path)
            problem = self._execution_problem(builder)
            if problem:
                raise ValidationError(problem)
            # Create as the desktop user, mode 0600, even when Nmap will run via sudo.
            xml_path = Path(self._xml_path)
            xml_path.unlink(missing_ok=True)
            xml_path.touch(mode=0o600)
        except (ValidationError, OSError) as exc:
            QMessageBox.warning(self, "Cannot start scan", str(exc))
            return
        self._active_options = replace(options)
        self._active_options.target = command[-1]
        self.command_preview.setPlainText(shlex.join(command))
        self._last_run = None
        self.console.clear()
        self.results_table.setRowCount(0)
        self.hosts_table.setRowCount(0)
        self.results_summary.setText("Scan in progress. Structured results appear after completion or cancellation.")
        self.tabs.setCurrentIndex(0)
        self._scanner = NmapScanner(command, self._xml_path, self)
        self._scanner.stdout.connect(self.append_output)
        self._scanner.stderr.connect(self.append_output)
        self._scanner.completed.connect(self._receive_result)
        self._scanner.finished.connect(self._scan_finished)
        self._scanner.finished.connect(self._scanner.deleteLater)
        self._set_running(True)
        self._started = time.monotonic()
        self._timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._timer.start()
        self._scanner.start()

    def _set_running(self, running: bool) -> None:
        self.options_panel.setEnabled(not running)
        self.target.setEnabled(not running)
        self.ipv6.setEnabled(not running)
        self.run_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.save_button.setEnabled(not running and self._last_run is not None)
        self._update_history_buttons()

    def _receive_result(self, run: ScanRun) -> None:
        self._last_run = run
        self._populate_results(run)
        if self._history is not None and self._active_options is not None:
            try:
                self._history.save_scan(self._timestamp, self._active_options, run)
                self.refresh_history()
            except (sqlite3.Error, OSError, HistoryError) as exc:
                self.history_status.setText(f"Could not save this scan to history: {exc}")

    def _populate_results(self, run: ScanRun) -> None:
        self.results_table.setRowCount(0)
        self.hosts_table.setRowCount(0)
        if not run.xml.strip():
            self.results_summary.setText("No XML results available. See Output for diagnostics.")
            return
        partial_note = ""
        try:
            hosts = NmapXmlParser().parse(run.xml)
        except NmapXmlError as exc:
            if not run.stopped:
                self.results_summary.setText(str(exc))
                return
            try:
                hosts = NmapXmlParser().parse(run.xml, allow_partial=True)
                partial_note = " Incomplete XML: only completed host elements are shown."
            except NmapXmlError as partial_exc:
                self.results_summary.setText(str(partial_exc))
                return
        rows, discovered = [], []
        for host in hosts:
            if host.status == "up":
                discovered.append([host.address, host.hostname, host.status, host.mac_address, host.vendor])
            if not host.ports:
                rows.append([host.address, host.status, "", "", "", "", ""])
            for port in host.ports:
                service = "/".join(value for value in (port.service.tunnel, port.service.name) if value)
                rows.append([host.address, host.status, str(port.port), port.protocol, port.state, service, port.service.description])
        self._fill_table(self.results_table, rows)
        self._fill_table(self.hosts_table, discovered)
        self.results_summary.setText(f"{len(hosts)} hosts · {len(discovered)} up · {sum(len(h.ports) for h in hosts)} explicit port records.{partial_note}")

    def _scan_finished(self) -> None:
        self._timer.stop()
        self._scanner = None
        self._set_running(False)
        run = self._last_run
        if run is not None:
            state = "Stopped" if run.stopped else ("Completed" if run.exit_code == 0 and not run.error else "Failed")
            self.statusBar().showMessage(f"{state} · {run.elapsed:.2f} s · exit code {run.exit_code}")
        self.update_preview()
        if self._close_requested:
            QTimer.singleShot(0, self.close)

    def _update_elapsed(self) -> None:
        self.statusBar().showMessage(f"Scanning · {time.monotonic() - self._started:.1f} s")

    def stop_scan(self) -> None:
        if self._scanner is not None:
            self._scanner.stop()
            self.stop_button.setEnabled(False)
            self.statusBar().showMessage("Stopping scan…")

    def save_results(self) -> None:
        if self._last_run is None:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save Results", "scan-results.txt", "Text output (*.txt)")
        if filename:
            try:
                Path(filename).write_text(self._last_run.output, encoding="utf-8")
            except OSError as exc:
                QMessageBox.warning(self, "Unable to save results", str(exc))

    def refresh_history(self, *_args) -> None:
        if self._history is None:
            self._update_history_buttons()
            return
        try:
            scans = self._history.list_scans()
            self.history_table.setSortingEnabled(False)
            self.history_table.setRowCount(len(scans))
            for row, scan in enumerate(scans):
                values = [scan.timestamp, scan.target, f"{scan.duration:.2f} s", scan.result,
                          str(scan.exit_code) if scan.exit_code is not None else "—", shlex.join(scan.command)]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.ItemDataRole.UserRole, scan.id)
                    item.setToolTip(value)
                    self.history_table.setItem(row, column, item)
            # Preserve the database's newest-first order until the user chooses a sort.
            self.history_status.setText(f"{len(scans)} most recent scans. Output and XML are stored locally.")
        except (sqlite3.Error, HistoryError) as exc:
            self.history_status.setText(f"Cannot read history: {exc}")
        self._update_history_buttons()

    def _update_history_buttons(self) -> None:
        selected = bool(self.history_table.selectedItems()) and self._history is not None
        idle = self._scanner is None
        self.open_history_button.setEnabled(selected and idle)
        self.rerun_history_button.setEnabled(selected and idle)
        self.copy_history_button.setEnabled(selected)

    def _selected_history(self):
        items = self.history_table.selectedItems()
        if not items or self._history is None:
            return None
        try:
            return self._history.get_scan(items[0].data(Qt.ItemDataRole.UserRole))
        except (sqlite3.Error, HistoryError) as exc:
            QMessageBox.warning(self, "Cannot load history", str(exc))
            return None

    def open_history(self, *_args) -> None:
        if self._scanner is not None:
            return
        entry = self._selected_history()
        if entry is None:
            return
        run = ScanRun(entry.command, entry.output, entry.xml, entry.exit_code,
                      entry.duration, entry.result == "stopped", entry.error)
        self._last_run = run
        self.console.setPlainText(run.output)
        self._populate_results(run)
        self.save_button.setEnabled(True)
        self.tabs.setCurrentIndex(1)
        self.statusBar().showMessage(f"History #{entry.id} · {entry.timestamp} · {entry.result} · {entry.duration:.2f} s")

    def copy_history_command(self) -> None:
        entry = self._selected_history()
        if entry is not None:
            QApplication.clipboard().setText(shlex.join(entry.command))

    def restore_options(self, options: ScanOptions) -> None:
        """Restore known typed options; never execute the command string stored in SQLite."""
        NmapCommandBuilder(options).build(self._xml_path)
        widgets = [self.target, self.scan_type, self.discovery, self.ports_mode, self.custom_ports,
                   self.service_detection, self.intensity, self.os_detection, self.default_scripts,
                   self.aggressive, self.timing, self.verbosity, self.use_sudo, self.ipv6]
        blockers = [QSignalBlocker(widget) for widget in widgets]
        try:
            self.target.setText(options.target)
            for combo, value in ((self.scan_type, options.scan_type), (self.discovery, options.discovery),
                                 (self.ports_mode, options.ports_mode)):
                combo.setCurrentIndex(combo.findData(value))
            self.custom_ports.setText(options.custom_ports)
            self.service_detection.setChecked(options.service_detection)
            self.os_detection.setChecked(options.os_detection)
            self.default_scripts.setChecked(options.default_scripts)
            self.aggressive.setChecked(options.aggressive)
            self.intensity.setValue(options.version_intensity)
            self.timing.setCurrentIndex(options.timing)
            self.verbosity.setCurrentIndex(options.verbosity)
            self.use_sudo.setChecked(options.use_sudo)
            self.ipv6.setChecked(options.ipv6)
        finally:
            for blocker in blockers:
                blocker.unblock()
        self.update_preview()

    def rerun_history(self) -> None:
        if self._scanner is not None:
            return
        entry = self._selected_history()
        if entry is None:
            return
        try:
            self.restore_options(entry.options)
        except (ValidationError, TypeError) as exc:
            QMessageBox.warning(self, "Cannot rerun scan", str(exc))
            return
        # Let Qt paint the regenerated command before starting the process.
        QTimer.singleShot(0, self.start_scan)

    def closeEvent(self, event) -> None:
        if self._scanner is not None:
            self._close_requested = True
            self.stop_scan()
            event.ignore()
            return
        self._temporary.cleanup()
        if self._history is not None:
            self._history.close()
            self._history = None
        event.accept()
