"""
Data containers for scan results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = ""
    version: str = ""
    banner: str = ""
    ssl_cert: Dict[str, Any] = field(default_factory=dict)
    banner_grabbed: bool = False
    cves: List[str] = field(default_factory=list)


@dataclass
class HostResult:
    host: str
    ip: str = ""
    mac: str = ""
    mac_vendor: str = ""
    os_guess: str = ""
    os_accuracy: float = 0.0
    reverse_dns: str = ""
    geo: Dict[str, Any] = field(default_factory=dict)
    asn: str = ""
    isp: str = ""
    org: str = ""
    whois: str = ""
    shodan: Dict[str, Any] = field(default_factory=dict)
    ports: List[PortResult] = field(default_factory=list)
    open_tcp: List[int] = field(default_factory=list)
    open_udp: List[int] = field(default_factory=list)
    latency_ms: float = 0.0
    up: bool = False
    traceroute: List[Dict[str, Any]] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    waf: str = ""
    cdn: str = ""
    cloud: str = ""
    honeypot: str = ""
    http_tech: Dict[str, str] = field(default_factory=dict)
    http_dirs: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    subdomains: List[Dict[str, str]] = field(default_factory=list)
    brute_creds: List[Dict[str, str]] = field(default_factory=list)
