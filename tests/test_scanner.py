import shutil
import socket
import sys

import pytest

from nmap_gui.command_builder import NmapCommandBuilder
from nmap_gui.models import ScanOptions
from nmap_gui.scanner import NmapScanner


def test_streams_before_completion_and_stops(tmp_path, qt_app, wait_until):
    scanner = NmapScanner([sys.executable, "-u", "-c",
        "import sys,time; print('first', flush=True); print('diagnostic',file=sys.stderr,flush=True); time.sleep(30)"],
        str(tmp_path / "scan.xml"))
    stdout, stderr, runs = [], [], []
    scanner.stdout.connect(stdout.append)
    scanner.stderr.connect(stderr.append)
    scanner.completed.connect(runs.append)
    scanner.start()
    try:
        wait_until(lambda: stdout and stderr)
        assert scanner.isRunning()
        assert "first" in "".join(stdout)
        assert "diagnostic" in "".join(stderr)
    finally:
        scanner.stop()
        assert scanner.wait(7000)
    qt_app.processEvents()
    assert runs[0].stopped
    assert runs[0].exit_code != 0
    assert runs[0].elapsed < 8


def test_missing_executable(tmp_path, qt_app, wait_until):
    scanner = NmapScanner([str(tmp_path / "absent-nmap")], str(tmp_path / "scan.xml"))
    runs = []
    scanner.completed.connect(runs.append)
    scanner.start()
    wait_until(lambda: runs and not scanner.isRunning())
    assert runs[0].exit_code is None
    assert "Unable to execute" in runs[0].error


def test_stop_before_start(tmp_path, qt_app, wait_until):
    scanner = NmapScanner(["should-not-execute"], str(tmp_path / "scan.xml"))
    runs = []
    scanner.completed.connect(runs.append)
    scanner.stop()
    scanner.start()
    wait_until(lambda: runs and not scanner.isRunning())
    assert runs[0].stopped
    assert not runs[0].error


def test_nonzero_exit_and_xml(tmp_path, qt_app, wait_until):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text("<nmaprun/>")
    scanner = NmapScanner([sys.executable, "-c", "raise SystemExit(7)"], str(xml_path))
    runs = []
    scanner.completed.connect(runs.append)
    scanner.start()
    wait_until(lambda: runs and not scanner.isRunning())
    assert runs[0].exit_code == 7
    assert runs[0].xml == "<nmaprun/>"


@pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is not installed")
def test_real_nmap_loopback(tmp_path, qt_app, wait_until):
    """Only loopback is scanned; an ephemeral local socket supplies a known open port."""
    try:
        server_socket = socket.socket()
    except PermissionError:
        pytest.skip("The execution sandbox forbids network sockets, including loopback")
    with server_socket as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        xml_path = tmp_path / "scan.xml"
        command = NmapCommandBuilder(ScanOptions(target="127.0.0.1", discovery="skip",
            ports_mode="custom", custom_ports=str(port))).build(str(xml_path))
        scanner = NmapScanner(command, str(xml_path))
        runs = []
        scanner.completed.connect(runs.append)
        scanner.start()
        try:
            wait_until(lambda: runs and not scanner.isRunning())
        finally:
            if scanner.isRunning():
                scanner.stop()
                scanner.wait(7000)
        assert runs[0].exit_code == 0, runs[0].output
        assert "Nmap done" in runs[0].output
        assert f'portid="{port}"' in runs[0].xml
        assert 'state="open"' in runs[0].xml


@pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is not installed")
def test_real_nmap_xml_without_network(tmp_path, qt_app, wait_until):
    """A real Nmap list scan creates XML without sending network probes."""
    xml_path = tmp_path / "scan.xml"
    scanner = NmapScanner(["nmap", "-sL", "-n", "-oX", str(xml_path), "127.0.0.1"], str(xml_path))
    runs = []
    scanner.completed.connect(runs.append)
    scanner.start()
    wait_until(lambda: runs and not scanner.isRunning())
    assert runs[0].exit_code == 0, runs[0].output
    assert "127.0.0.1" in runs[0].xml
    assert "Nmap done" in runs[0].output
