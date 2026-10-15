"""Interpret Nmap XML; raw output is retained even if XML is incomplete."""

import io
import re
import xml.etree.ElementTree as ET

from .models import HostResult, PortResult, ServiceResult


class NmapXmlError(ValueError):
    """XML is invalid, unsupported or exceeds the local parser limit."""


class NmapXmlParser:
    MAX_XML_CHARACTERS = 64 * 1024 * 1024

    def parse(self, xml: str, *, allow_partial: bool = False) -> list[HostResult]:
        if len(xml) > self.MAX_XML_CHARACTERS:
            raise NmapXmlError("XML exceeds the 64 MiB character limit; raw output is still available.")
        # Accept Nmap's ordinary DOCTYPE, but never user-defined entities.
        if re.search(r"<!\s*ENTITY\b", xml, re.IGNORECASE):
            raise NmapXmlError("XML entity declarations are not supported.")
        hosts = []
        root_seen = False
        try:
            for event, element in ET.iterparse(io.StringIO(xml), events=("start", "end")):
                if not root_seen:
                    if element.tag != "nmaprun":
                        raise NmapXmlError("Expected a Nmap XML document with a nmaprun root.")
                    root_seen = True
                if event == "end" and element.tag == "host":
                    hosts.append(self._host(element))
                    element.clear()
        except ET.ParseError as exc:
            if not allow_partial or not root_seen:
                raise NmapXmlError(f"Invalid or incomplete Nmap XML: {exc}") from exc
        return hosts

    @staticmethod
    def _host(element: ET.Element) -> HostResult:
        addresses = element.findall("address")
        address = next((a.get("addr", "") for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}), "unknown")
        mac = next((a for a in addresses if a.get("addrtype") == "mac"), None)
        status = element.find("status")
        host = HostResult(
            address=address, status=status.get("state", "unknown") if status is not None else "unknown",
            hostname=", ".join(dict.fromkeys(h.get("name", "") for h in element.findall("hostnames/hostname") if h.get("name"))),
            mac_address=mac.get("addr", "") if mac is not None else "",
            vendor=mac.get("vendor", "") if mac is not None else "",
        )
        for port in element.findall("ports/port"):
            try:
                number = int(port.get("portid", ""))
                if not 0 <= number <= 65535:
                    raise ValueError("out of range")
            except ValueError as exc:
                raise NmapXmlError("Invalid port number in XML.") from exc
            state = port.find("state")
            service = port.find("service")
            details = ServiceResult() if service is None else ServiceResult(
                name=service.get("name", ""), product=service.get("product", ""),
                version=service.get("version", ""), extra_info=service.get("extrainfo", ""),
                tunnel=service.get("tunnel", ""),
            )
            host.ports.append(PortResult(number, port.get("protocol", ""),
                state.get("state", "unknown") if state is not None else "unknown", details))
        return host
