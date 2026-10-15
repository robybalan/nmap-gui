import pytest

from nmap_gui.parser import NmapXmlError, NmapXmlParser

XML = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun><host><status state="up"/>
<address addr="192.168.56.101" addrtype="ipv4"/>
<address addr="08:00:27:AA:BB:CC" addrtype="mac" vendor="Lab vendor"/>
<hostnames><hostname name="lab.local"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.2" extrainfo="protocol 2.0"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/></port>
</ports></host><host><status state="down"/><address addr="2001:db8::1" addrtype="ipv6"/></host></nmaprun>'''


def test_services_hosts_and_missing_fields():
    first, second = NmapXmlParser().parse(XML)
    assert first.address == "192.168.56.101"
    assert first.status == "up"
    assert first.hostname == "lab.local"
    assert first.mac_address == "08:00:27:AA:BB:CC"
    assert first.vendor == "Lab vendor"
    assert first.ports[0].port == 22
    assert first.ports[0].service.description == "OpenSSH 9.2 protocol 2.0"
    assert first.ports[1].protocol == "udp"
    assert first.ports[1].state == "open|filtered"
    assert first.ports[1].service.name == ""
    assert second.address == "2001:db8::1"
    assert second.status == "down"
    assert not second.ports


def test_partial_scan_recovers_only_complete_hosts():
    xml = XML.removesuffix("</nmaprun>") + '<host><status state="up"/>'
    with pytest.raises(NmapXmlError):
        NmapXmlParser().parse(xml)
    assert len(NmapXmlParser().parse(xml, allow_partial=True)) == 2


@pytest.mark.parametrize("xml", ["", "<bad/>", "<nmaprun><host>",
    '<!DOCTYPE nmaprun [<!ENTITY x "danger">]><nmaprun>&x;</nmaprun>',
    '<nmaprun><host><ports><port portid="wrong"/></ports></host></nmaprun>'])
def test_bad_xml(xml):
    with pytest.raises(NmapXmlError):
        NmapXmlParser().parse(xml)


def test_empty_run_and_unknown_host():
    assert NmapXmlParser().parse("<nmaprun/>") == []
    host = NmapXmlParser().parse("<nmaprun><host/></nmaprun>")[0]
    assert (host.address, host.status) == ("unknown", "unknown")


def test_oversize(monkeypatch):
    monkeypatch.setattr(NmapXmlParser, "MAX_XML_CHARACTERS", 10)
    with pytest.raises(NmapXmlError):
        NmapXmlParser().parse(XML)
