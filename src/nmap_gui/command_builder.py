"""Build argv lists; shell quoting is used only for the visible preview."""

from dataclasses import replace
import shlex

from .models import ScanOptions
from .validators import ValidationError, target_is_ipv6, validate_ports, validate_target

SCAN_FLAGS = {"discovery": "-sn", "syn": "-sS", "connect": "-sT", "udp": "-sU", "ack": "-sA"}
DISCOVERY_FLAGS = {"default": None, "skip": "-Pn", "syn": "-PS", "ack": "-PA", "udp": "-PU"}
PORT_MODES = {"default", "top10", "top100", "top1000", "all", "custom"}


class NmapCommandBuilder:
    def __init__(self, options: ScanOptions | None = None):
        self.options = replace(options) if options else ScanOptions()

    def set_target(self, target: str) -> "NmapCommandBuilder":
        self.options.target = validate_target(target)
        return self

    def enable_syn_scan(self) -> "NmapCommandBuilder":
        self.options.scan_type = "syn"
        return self

    def enable_service_detection(self) -> "NmapCommandBuilder":
        self.options.service_detection = True
        return self

    def set_ports(self, ports: str) -> "NmapCommandBuilder":
        self.options.custom_ports = validate_ports(ports)
        self.options.ports_mode = "custom"
        return self

    @property
    def requires_elevation(self) -> bool:
        o = self.options
        return (o.scan_type in {"syn", "udp", "ack"} or o.os_detection or o.aggressive
                or o.discovery in {"ack", "udp"})

    def build(self, xml_path: str | None = None) -> list[str]:
        o = self.options
        target = validate_target(o.target)
        if o.scan_type not in SCAN_FLAGS or o.discovery not in DISCOVERY_FLAGS:
            raise ValidationError("Unknown scan or discovery type.")
        if o.ports_mode not in PORT_MODES:
            raise ValidationError("Unknown port selection.")
        if type(o.timing) is not int or not 0 <= o.timing <= 5:
            raise ValidationError("Timing must be between T0 and T5.")
        if type(o.version_intensity) is not int or not 0 <= o.version_intensity <= 9:
            raise ValidationError("Version intensity must be between 0 and 9.")
        if type(o.verbosity) is not int or o.verbosity not in {0, 1, 2}:
            raise ValidationError("Invalid verbosity.")
        if o.scan_type == "discovery" and (o.discovery == "skip" or o.ports_mode != "default"
                or o.service_detection or o.os_detection or o.default_scripts or o.aggressive):
            raise ValidationError("Ping Scan cannot be combined with port scanning, detection, scripts or -Pn.")
        argv = ["sudo", "-n", "--", "nmap"] if o.use_sudo else ["nmap"]
        if o.ipv6 or target_is_ipv6(target):
            argv.append("-6")
        argv.append(SCAN_FLAGS[o.scan_type])
        if DISCOVERY_FLAGS[o.discovery]:
            argv.append(DISCOVERY_FLAGS[o.discovery])
        if o.aggressive:
            argv.append("-A")
        else:
            if o.service_detection:
                argv.append("-sV")
            if o.os_detection:
                argv.append("-O")
            if o.default_scripts:
                argv.append("-sC")
        if o.service_detection or o.aggressive:
            argv.extend(["--version-intensity", str(o.version_intensity)])
        if o.ports_mode.startswith("top"):
            argv.extend(["--top-ports", o.ports_mode[3:]])
        elif o.ports_mode == "all":
            argv.append("-p-")
        elif o.ports_mode == "custom":
            argv.extend(["-p", validate_ports(o.custom_ports)])
        argv.append(f"-T{o.timing}")
        if o.verbosity:
            argv.append("-" + "v" * o.verbosity)
        if xml_path is not None:
            if not xml_path or xml_path == "-" or "\x00" in xml_path:
                raise ValidationError("XML output must use a file, leaving stdout available for streaming.")
            argv.extend(["-oX", str(xml_path)])
        argv.append(target)
        return argv

    def preview(self, xml_path: str | None = None) -> str:
        return shlex.join(self.build(xml_path))
