"""Data shared by the builder, parser, scanner and persistence layer."""

from dataclasses import dataclass, field


@dataclass
class ScanOptions:
    target: str = ""
    scan_type: str = "connect"
    discovery: str = "default"
    ports_mode: str = "default"
    custom_ports: str = ""
    service_detection: bool = False
    version_intensity: int = 7
    os_detection: bool = False
    default_scripts: bool = False
    aggressive: bool = False
    timing: int = 3
    verbosity: int = 0
    use_sudo: bool = False
    ipv6: bool = False


@dataclass
class ServiceResult:
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""

    @property
    def description(self) -> str:
        return " ".join(value for value in (self.product, self.version, self.extra_info) if value)


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: ServiceResult = field(default_factory=ServiceResult)


@dataclass
class HostResult:
    address: str
    status: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanRun:
    command: list[str]
    output: str
    xml: str
    exit_code: int | None
    elapsed: float
    stopped: bool = False
    error: str = ""


@dataclass
class HistoryEntry:
    id: int
    timestamp: str
    target: str
    command: list[str]
    options: ScanOptions
    duration: float
    result: str
    exit_code: int | None
    output: str
    xml: str
    error: str = ""


@dataclass
class HistorySummary:
    id: int
    timestamp: str
    target: str
    command: list[str]
    duration: float
    result: str
    exit_code: int | None
