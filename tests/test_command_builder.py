import pytest

from nmap_gui.command_builder import NmapCommandBuilder
from nmap_gui.models import ScanOptions
from nmap_gui.validators import ValidationError


def build(**kwargs):
    return NmapCommandBuilder(ScanOptions(target="127.0.0.1", **kwargs)).build()


def test_fluent_builder():
    command = (NmapCommandBuilder().set_target("192.168.56.101").enable_syn_scan()
               .enable_service_detection().set_ports("22,80,443").build())
    assert command == ["nmap", "-sS", "-sV", "--version-intensity", "7", "-p", "22,80,443", "-T3", "192.168.56.101"]


@pytest.mark.parametrize("scan,flag", [("syn", "-sS"), ("connect", "-sT"), ("udp", "-sU"), ("ack", "-sA"), ("discovery", "-sn")])
def test_scan_modes(scan, flag):
    assert build(scan_type=scan) == ["nmap", flag, "-T3", "127.0.0.1"]


@pytest.mark.parametrize("mode,flags", [("default", []), ("top10", ["--top-ports", "10"]), ("top100", ["--top-ports", "100"]),
    ("top1000", ["--top-ports", "1000"]), ("all", ["-p-"]), ("custom", ["-p", "22,80"])])
def test_port_modes(mode, flags):
    assert build(ports_mode=mode, custom_ports="22,80") == ["nmap", "-sT", *flags, "-T3", "127.0.0.1"]


@pytest.mark.parametrize("mode,flag", [("skip", "-Pn"), ("syn", "-PS"), ("ack", "-PA"), ("udp", "-PU")])
def test_discovery(mode, flag):
    assert flag in build(discovery=mode)


def test_detection_and_timing():
    assert build(service_detection=True, version_intensity=9, os_detection=True, default_scripts=True, timing=4, verbosity=2) == [
        "nmap", "-sT", "-sV", "-O", "-sC", "--version-intensity", "9", "-T4", "-vv", "127.0.0.1"]


def test_aggressive_deduplicates_features():
    command = build(aggressive=True, service_detection=True, os_detection=True, default_scripts=True)
    assert "-A" in command
    assert not {"-sV", "-O", "-sC"}.intersection(command)


def test_sudo_and_xml_preview():
    builder = NmapCommandBuilder(ScanOptions(target="127.0.0.1", use_sudo=True))
    command = builder.build("/tmp/a b.xml")
    assert command[:4] == ["sudo", "-A", "--", "nmap"]
    assert command[-3:] == ["-oX", "/tmp/a b.xml", "127.0.0.1"]
    assert "'/tmp/a b.xml'" in builder.preview("/tmp/a b.xml")


@pytest.mark.parametrize("target", ["::1", "2001:db8::/64"])
def test_ipv6(target):
    assert "-6" in NmapCommandBuilder(ScanOptions(target=target)).build()


def test_dns_ipv6():
    assert "-6" in NmapCommandBuilder(ScanOptions(target="lab.local", ipv6=True)).build()


@pytest.mark.parametrize("kwargs", [{"timing": 6}, {"verbosity": 3}, {"version_intensity": -1}, {"scan_type": "bad"},
    {"discovery": "bad"}, {"ports_mode": "bad"}, {"scan_type": "discovery", "discovery": "skip"},
    {"scan_type": "discovery", "service_detection": True}, {"scan_type": "discovery", "ports_mode": "all"}])
def test_invalid_options(kwargs):
    with pytest.raises(ValidationError):
        build(**kwargs)


@pytest.mark.parametrize("kwargs,expected", [({"scan_type": "connect"}, False), ({"scan_type": "syn"}, True),
    ({"scan_type": "udp"}, True), ({"scan_type": "ack"}, True), ({"os_detection": True}, True),
    ({"aggressive": True}, True), ({"scan_type": "discovery"}, False), ({"discovery": "udp"}, True)])
def test_privileges(kwargs, expected):
    assert NmapCommandBuilder(ScanOptions(**kwargs)).requires_elevation is expected
