"""
Configuration management — immutable ScanConfig, platform detection, constants.
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── OS detection ─────────────────────────────────────────────────────────
OS_NAME: str = sys.platform.lower()
IS_WINDOWS: bool = OS_NAME.startswith("win")
IS_MACOS: bool = OS_NAME.startswith("darwin")
IS_LINUX: bool = OS_NAME.startswith("linux")
IS_TERMUX: bool = IS_LINUX and (
    "com.termux" in (os.environ.get("PREFIX", "") or "")
    or os.path.exists("/data/data/com.termux/files/usr")
)

# ── Optional import detection (flags set at module load) ─────────────────
HAS_SCAPY: bool = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr1, sr  # type: ignore
    HAS_SCAPY = True
except ImportError:
    pass

HAS_CRYPTO: bool = False
try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    HAS_CRYPTO = True
except ImportError:
    pass

HAS_PARAMIKO: bool = False
try:
    import paramiko  # type: ignore
    HAS_PARAMIKO = True
except ImportError:
    pass

HAS_DNS: bool = False
try:
    import dns.resolver  # type: ignore
    HAS_DNS = True
except ImportError:
    pass

# ── Constants ────────────────────────────────────────────────────────────
SSL_PORTS: frozenset = frozenset({443, 8443, 465, 993, 995})
MAX_GLOBAL_THREADS: int = 1024
MAX_CIDR_HOSTS: int = 65536
BOX_WIDTH: int = 70
BANNER_GRAB_MAX: int = 65536

_SSL_CTX_CACHE: Dict[str, ssl.SSLContext] = {}
_SSL_CTX_LOCK: threading.Lock = threading.Lock()
_ssl_warned: bool = False

# ── Pre-compiled patterns ────────────────────────────────────────────────
SHELL_META: re.Pattern = re.compile(r'[\n\r\t|;&`$(){}]')
_SEP: str = re.escape(os.sep)
INVALID_PATH: re.Pattern = re.compile(rf'(?:^|{_SEP})\.\.(?:{_SEP}|$)')
TTL_RE: re.Pattern = re.compile(rb'(?:ttl|TTL)=(\d+)')
TRACEROUTE_RE: re.Pattern = re.compile(r'\s*(\d+)\s+(\S+)')
BANNER_VER_RE: re.Pattern = re.compile(r'(\d+\.\d+(?:\.\d+)?)')
SSH_BANNER_RE: re.Pattern = re.compile(r'SSH-\d+\.\d+-\S+')


def _get_ssl_ctx(warn: bool = False) -> ssl.SSLContext:
    global _ssl_warned
    if warn and not _ssl_warned:
        logger.warning("SSL certificate verification is DISABLED — connection security is not enforced")
        _ssl_warned = True
    with _SSL_CTX_LOCK:
        if "default" not in _SSL_CTX_CACHE:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers('ALL:@SECLEVEL=0')
            except ssl.SSLError:
                pass
            _SSL_CTX_CACHE["default"] = ctx
        return _SSL_CTX_CACHE["default"]


BANNER_ART: str = r"""
╔══════════════════════════════════════════════════════════╗
║ _____  _____   ____  __  __          _____  _____  ______ _____  ║
║|  __ \|  __ \ / __ \|  \/  |   /\   |  __ \|  __ \|  ____|  __ \ ║
║| |__) | |__) | |  | | \  / |  /  \  | |__) | |__) | |__  | |__) |║
║|  ___/|  _  /| |  | | |\/| | / /\ \ |  ___/|  ___/|  __| |  _  / ║
║| |    | | \ \| |__| | |  | |/ ____ \| |    | |    | |____| | \ \ ║
║|_|    |_|  \_\\____/|_|  |_/_/    \_\_|    |_|    |______|_|  \_\║
║                                                                  ║
║          PRO Network Mapper — cross-platform    v3.1.0           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════╝
"""


def _supports_color() -> bool:
    if IS_WINDOWS:
        try:
            return bool(os.environ.get("TERM") or os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))
        except Exception:
            return False
    return sys.stdout.isatty()


def _is_valid_target(t: str) -> bool:
    if not t or len(t) > 255 or t.startswith(".") or t.endswith("."):
        return False
    if ".." in t:
        return False
    return not bool(SHELL_META.search(t))


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname).1s %(message)s",
        stream=sys.stderr,
    )


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration. Create via ``ScanConfig.from_args()``."""
    timeout: float = 2.0
    threads: int = 100
    rate_limit: int = 0
    random_delay: Tuple[float, float] = (0.0, 0.0)
    proxy: Optional[str] = None
    decoy_ips: Tuple[str, ...] = ()
    verbose: bool = False
    source_port: Optional[int] = None
    shodan_key: str = ""
    dns_server: Optional[str] = None
    fragment: bool = False
    ttl: int = 64
    badsum: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "ScanConfig":
        to_val: float = 2.0
        thr_val: int = 100
        rate_val: int = 0

        if args.timing is not None:
            timing_map = {
                0: (5.0, 5, 1), 1: (3.0, 10, 5), 2: (2.0, 50, 50),
                3: (1.5, 100, 0), 4: (1.0, 200, 0), 5: (0.5, 500, 0),
            }
            to_val, thr_val, rate_val = timing_map.get(args.timing, timing_map[3])

        if args.timeout is not None:
            to_val = args.timeout
        if args.threads is not None:
            thr_val = args.threads
        if args.rate_limit is not None:
            rate_val = args.rate_limit

        rdelay: Tuple[float, float] = (0.0, 0.0)
        if args.random_delay:
            try:
                parts = args.random_delay.split(",")
                rdelay = (float(parts[0]), float(parts[1]))
            except (ValueError, IndexError):
                pass

        return cls(
            timeout=to_val,
            threads=thr_val,
            rate_limit=rate_val,
            random_delay=rdelay,
            proxy=args.proxy,
            decoy_ips=tuple(d.strip() for d in args.decoy.split(",")) if args.decoy else (),
            verbose=args.verbose,
            source_port=args.source_port,
            shodan_key=os.environ.get("SHODAN_API_KEY", ""),
            dns_server=args.dns_server,
            fragment=args.fragment or False,
            ttl=args.ttl or 64,
            badsum=args.badsum or False,
        )


# ── Global runtime state ─────────────────────────────────────────────────
_runtime_cfg: ScanConfig = ScanConfig()


def cfg() -> ScanConfig:
    return _runtime_cfg


def cfg_set(c: ScanConfig) -> None:
    global _runtime_cfg
    _runtime_cfg = c
