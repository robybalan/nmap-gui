"""Run argv in a worker thread and stream both pipes without blocking Qt."""

import codecs
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time

from PyQt6.QtCore import QThread, pyqtSignal as Signal

from .models import ScanRun


class NmapScanner(QThread):
    stdout = Signal(str)
    stderr = Signal(str)
    completed = Signal(object)

    def __init__(self, command: list[str], xml_path: str, parent=None):
        super().__init__(parent)
        self.command = list(command)
        self.xml_path = Path(xml_path)
        self._stop_requested = threading.Event()

    def stop(self) -> None:
        """Request cancellation; signals and process reaping happen in the worker."""
        self._stop_requested.set()

    @staticmethod
    def _signal_group(process: subprocess.Popen, sig: int) -> None:
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def run(self) -> None:
        started = time.monotonic()
        output: list[str] = []
        error = ""
        xml = ""
        process = None
        exit_code = None
        try:
            if self._stop_requested.is_set():
                return
            # A separate session permits stopping the process tree, including sudo's monitor.
            # stdin is closed: sudo -n fails clearly rather than waiting for a password.
            process = subprocess.Popen(
                self.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, start_new_session=True, bufsize=0,
            )
            with selectors.DefaultSelector() as selector:
                decoders = {}
                for pipe, emitter in ((process.stdout, self.stdout), (process.stderr, self.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, emitter)
                    decoders[pipe] = codecs.getincrementaldecoder("utf-8")("replace")
                stop_started = None
                term_sent = False
                kill_sent = False
                while selector.get_map() or process.poll() is None:
                    now = time.monotonic()
                    if self._stop_requested.is_set() and stop_started is None:
                        self._signal_group(process, signal.SIGINT)
                        stop_started = now
                    if stop_started is not None and now - stop_started >= 3 and not term_sent:
                        self._signal_group(process, signal.SIGTERM)
                        term_sent = True
                    if stop_started is not None and now - stop_started >= 5 and not kill_sent:
                        self._signal_group(process, signal.SIGKILL)
                        kill_sent = True
                    for key, _ in selector.select(timeout=0.1):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        text = decoders[key.fileobj].decode(chunk, final=not chunk)
                        if text:
                            output.append(text)
                            key.data.emit(text)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                exit_code = process.wait()
        except (OSError, ValueError) as exc:
            error = f"Unable to execute scan: {exc}"
            self.stderr.emit(error + "\n")
            output.append(error + "\n")
        finally:
            if process is not None:
                if process.poll() is None:
                    self._signal_group(process, signal.SIGKILL)
                    process.wait()
                exit_code = process.returncode
                for pipe in (process.stdout, process.stderr):
                    if pipe and not pipe.closed:
                        pipe.close()
            try:
                if self.xml_path.exists():
                    xml = self.xml_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                error = f"Cannot read XML results: {exc}"
                self.stderr.emit(error + "\n")
            self.completed.emit(ScanRun(
                self.command, "".join(output), xml, exit_code,
                time.monotonic() - started, self._stop_requested.is_set(), error,
            ))
