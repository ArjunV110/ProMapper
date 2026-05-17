"""
Core scanning engine — DNS resolution, port scanning, ping, traceroute, banner/SSL.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from promapper.config import (
    SSL_PORTS, MAX_CIDR_HOSTS, BANNER_GRAB_MAX,
    IS_WINDOWS, IS_MACOS, IS_TERMUX, HAS_SCAPY, HAS_DNS, HAS_CRYPTO,
    ScanConfig, cfg, _get_ssl_ctx,
    TTL_RE, TRACEROUTE_RE, BANNER_VER_RE,
)
from promapper.datatypes import PortResult, HostResult

logger = logging.getLogger(__name__)

# Optional imports — guarded by feature flags set in config.py
try:
    if HAS_SCAPY:
        from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr1, sr
except ImportError:
    pass
if HAS_CRYPTO:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        pass
try:
    import dns.resolver
except ImportError:
    pass


# ── DNS / Resolution ────────────────────────────────────────────────────
def resolve_host(host: str, dns_server: Optional[str] = None, retries: int = 2) -> Optional[str]:
    for attempt in range(retries + 1):
        try:
            if dns_server and HAS_DNS:
                try:
                    res = dns.resolver.Resolver()
                    res.nameservers = [dns_server]
                    res.timeout = cfg().timeout
                    res.lifetime = cfg().timeout * 2
                    return str(res.resolve(host, "A")[0])
                except Exception:
                    if attempt < retries:
                        time.sleep(0.5 * (attempt + 1))
                    continue
            return socket.gethostbyname(host)
        except socket.gaierror:
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
    logger.debug("resolve_host(%s) failed after %d retries", host, retries)
    return None


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def get_service_name(port: int, proto: str = "tcp") -> str:
    try:
        if not (0 <= port <= 65535):
            return "unknown"
        name = socket.getservbyport(port, proto)
        # Sanitize: strip whitespace, newlines, and control characters
        name = name.split("\n")[0].split("\r")[0].strip()
        name = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', name)
        return name if name else "unknown"
    except (OSError, OverflowError):
        return "unknown"


def parse_ports(port_str: str) -> List[int]:
    if not port_str or not port_str.strip():
        return []
    ports: set = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = map(int, part.split("-"))
                if lo > hi:
                    lo, hi = hi, lo
                ports.update(range(max(0, lo), min(65535, hi) + 1))
            except ValueError:
                logger.error("Invalid port range: %s", part)
        else:
            try:
                p = int(part)
                if 0 <= p <= 65535:
                    ports.add(p)
                else:
                    logger.error("Port out of range: %d", p)
            except ValueError:
                logger.error("Invalid port: %s", part)
    return sorted(ports)


def expand_targets(targets: List[str]) -> List[Tuple[str, str]]:
    expanded: List[Tuple[str, str]] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts = list(net)
            if len(hosts) > MAX_CIDR_HOSTS:
                logger.warning("%s expands to %d hosts, limiting to %d", t, len(hosts), MAX_CIDR_HOSTS)
                hosts = hosts[:MAX_CIDR_HOSTS]
            if not hosts:
                expanded.append((t, str(net.network_address)))
            for ip in hosts:
                expanded.append((t, str(ip)))
        except ValueError:
            expanded.append((t, t))
    return expanded


# ── TCP / UDP Raw Socket Scanning ───────────────────────────────────────
def make_sock(timeout_val: Optional[float] = None, source_port: Optional[int] = None) -> socket.socket:
    t = timeout_val if timeout_val is not None else cfg().timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(t)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass
    src = source_port or cfg().source_port
    if src:
        try:
            sock.bind(("0.0.0.0", src))
        except OSError:
            logger.debug("source_port bind(%d) failed", src)
    return sock


def tcp_connect_scan(host: str, port: int, timeout_val: Optional[float] = None,
                     source_port: Optional[int] = None) -> Optional[bool]:
    sock = None
    try:
        sock = make_sock(timeout_val, source_port)
        sock.connect((host, port))
        return True
    except socket.timeout:
        return None
    except (ConnectionRefusedError, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def _udp_payload(port: int) -> bytes:
    proto_payloads = {
        53: b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
        67: b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        68: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        69: b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        123: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x7f\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00",
        162: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x7f\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00",
        514: b"\x00\x00\x00\x00\x00\x00\x00\x00",
        520: b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x00\x00\x01\x00\x01",
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\nMX: 1\r\n\r\n",
        5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }
    return proto_payloads.get(port, b"\x00" * 8)


def udp_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    t = timeout_val or cfg().timeout
    payload = _udp_payload(port)

    if HAS_SCAPY:
        try:
            pkt = IP(dst=host, ttl=cfg().ttl) / UDP(dport=port) / payload
            if cfg().fragment:
                pkt[IP].flags = 1
            ans = sr1(pkt, timeout=t, verbose=0)
            if ans is None:
                return None
            if ans.haslayer(ICMP):
                icmp_type = ans.getlayer(ICMP).type
                icmp_code = ans.getlayer(ICMP).code
                if icmp_type == 3:
                    if icmp_code in (1, 2, 3, 9, 10, 13):
                        return False
                    return None
                return None
            if ans.haslayer(UDP):
                return True
            return None
        except Exception as e:
            logger.debug("UDP scapy scan error: %s", e)
            return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(t)
        sock.sendto(payload, (host, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return None
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except OSError:
        return False


# ── Scapy helpers ───────────────────────────────────────────────────────
def _make_tcp_pkt(dst: str, dport: int, flags: str) -> IP:
    conf = cfg()
    pkt = IP(dst=dst, ttl=conf.ttl) / TCP(dport=dport, flags=flags)
    if conf.badsum:
        pkt[TCP].chksum = 0xFFFF
    if conf.fragment:
        pkt[IP].flags = 1
    return pkt


# ── Scapy-based scans ───────────────────────────────────────────────────
def syn_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        logger.debug("SYN scan needs scapy, falling back to connect")
        return tcp_connect_scan(host, port, timeout_val, cfg().source_port)
    try:
        ans = sr1(_make_tcp_pkt(host, port, "S"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return None
        if ans.haslayer(TCP):
            flags = ans.getlayer(TCP).flags
            if flags & 0x12 == 0x12:
                return True
            if flags & 0x04:
                return False
        return None
    except Exception as e:
        logger.debug("SYN scan error: %s", e)
        return None


def fin_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, "F"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(ICMP):
            return None
        if ans.haslayer(TCP) and (ans.getlayer(TCP).flags & 0x04):
            return False
    except Exception:
        pass
    return None


def null_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, ""),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(ICMP):
            return None
        if ans.haslayer(TCP) and (ans.getlayer(TCP).flags & 0x04):
            return False
    except Exception:
        pass
    return None


def xmas_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, "FPU"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(ICMP):
            return None
        if ans.haslayer(TCP) and (ans.getlayer(TCP).flags & 0x04):
            return False
    except Exception:
        pass
    return None


def ack_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, "A"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans and ans.haslayer(TCP) and (ans.getlayer(TCP).flags & 0x04):
            return True
    except Exception:
        pass
    return False


def window_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, "A"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return None
        if ans.haslayer(TCP):
            return ans.getlayer(TCP).window > 0
    except Exception:
        pass
    return None


def maimon_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(_make_tcp_pkt(host, port, "FP"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(ICMP):
            return None
        if ans.haslayer(TCP) and (ans.getlayer(TCP).flags & 0x04):
            return False
    except Exception:
        pass
    return None


def idle_scan(zombie: str, target: str, port: int,
              timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        logger.debug("Idle scan requires scapy")
        return None

    def get_ipid(host: str) -> Optional[int]:
        try:
            ans = sr1(_make_tcp_pkt(host, 445, "SA"),
                      timeout=timeout_val or cfg().timeout, verbose=0)
            if ans and ans.haslayer(IP):
                return ans.getlayer(IP).id
        except Exception:
            pass
        return None

    try:
        orig = get_ipid(zombie)
        if orig is None:
            return None
        conf = cfg()
        probe = IP(src=zombie, dst=target, ttl=conf.ttl) / TCP(dport=port, flags="S")
        if conf.badsum:
            probe[TCP].chksum = 0xFFFF
        if conf.fragment:
            probe[IP].flags = 1
        sr(probe, timeout=timeout_val or cfg().timeout, verbose=0)
        after = get_ipid(zombie)
        if after is None:
            return None
        if after == orig + 2:
            return True
        if after == orig + 1:
            return False
    except Exception as e:
        logger.debug("idle_scan error: %s", e)
    return None


SCAN_FUNCS: Dict[str, Callable[..., Optional[bool]]] = {
    "syn": syn_scan, "fin": fin_scan, "null": null_scan,
    "xmas": xmas_scan, "ack": ack_scan, "window": window_scan, "maimon": maimon_scan,
}


def scan_single_port(host: str, ip: str, port: int, scan_type: str = "connect",
                     timeout_val: Optional[float] = None) -> PortResult:
    result = PortResult(port=port)
    if scan_type == "udp":
        result.protocol = "udp"
        s = udp_scan(ip, port, timeout_val)
        result.state = "open" if s is True else "closed" if s is False else "open|filtered"
        return result
    if scan_type == "connect":
        s = tcp_connect_scan(ip, port, timeout_val, cfg().source_port)
        result.state = "open" if s is True else "closed" if s is False else "filtered"
        return result
    if scan_type == "idle":
        return result
    func = SCAN_FUNCS.get(scan_type)
    if func is None:
        result.state = "error"
        return result
    s = func(ip, port, timeout_val)
    if scan_type in ("fin", "null", "xmas", "maimon"):
        result.state = "open|filtered" if s is True else "closed" if s is False else "filtered"
    elif scan_type == "ack":
        result.state = "unfiltered" if s else "filtered"
    elif scan_type == "window":
        result.state = "open" if s is True else "closed" if s is False else "filtered"
    else:
        result.state = "open" if s is True else "closed" if s is False else "filtered"
    return result


# ── ARP Discovery ───────────────────────────────────────────────────────
def arp_discovery(network: str) -> List[Tuple[str, str]]:
    if not HAS_SCAPY:
        return []
    hosts: List[Tuple[str, str]] = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip_addr in net.hosts():
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip_addr))
                ans = sr1(pkt, timeout=1, verbose=0)
                if ans and ans.haslayer(ARP):
                    hosts.append((str(ip_addr), ans.getlayer(ARP).hwsrc))
            except Exception:
                pass
    except ValueError:
        pass
    return hosts


# ── Ping / ICMP ─────────────────────────────────────────────────────────
def _ping_cmd(timeout_sec: float = 2) -> List[str]:
    t_int = int(max(timeout_sec, 1))
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(t_int * 1000)]
    if IS_MACOS:
        return ["ping", "-c", "1", "-W", str(t_int * 1000)]
    return ["ping", "-c", "1", "-W", str(t_int)]


def ping_sweep(host: str, timeout_val: Optional[float] = None) -> bool:
    try:
        t = timeout_val or max(1.0, cfg().timeout)
        cmd = _ping_cmd(t) + [host]
        res = subprocess.run(cmd, capture_output=True, timeout=t + 2)
        if res.returncode != 0:
            return False
        if IS_WINDOWS:
            out = res.stdout.lower()
            return b"reply from" in out or b"ttl=" in out
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def icmp_ping(host: str, timeout_val: Optional[float] = None) -> bool:
    if HAS_SCAPY:
        try:
            pkt = IP(dst=host, ttl=cfg().ttl) / ICMP()
            if cfg().fragment:
                pkt[IP].flags = 1
            ans = sr1(pkt, timeout=timeout_val or cfg().timeout, verbose=0)
            return ans is not None
        except Exception:
            pass
    return ping_sweep(host, timeout_val)


# ── Traceroute ──────────────────────────────────────────────────────────
def _traceroute_cmd(host: str, timeout_val: float) -> List[str]:
    t_int = int(timeout_val)
    if IS_WINDOWS:
        return ["tracert", "-h", "30", "-w", str(max(t_int * 1000, 1000)), host]
    if IS_MACOS:
        return ["traceroute", "-n", "-q", "1", "-m", "30", "-W", str(t_int * 1000), host]
    return ["traceroute", "-n", "-q", "1", "-m", "30", "-w", str(t_int), host]


def traceroute(host: str, max_hops: int = 30, timeout_val: Optional[float] = None) -> List[Dict[str, Any]]:
    hops: List[Dict[str, Any]] = []
    t = timeout_val or cfg().timeout

    # Try Scapy-based traceroute first (raw ICMP, needs root)
    if HAS_SCAPY:
        for ttl in range(1, max_hops + 1):
            try:
                pkt = IP(dst=host, ttl=ttl) / ICMP()
                pkt.sent_time = time.time()
                ans = sr1(pkt, timeout=t, verbose=0)
                if ans:
                    hop_ip = ans.getlayer(IP).src
                    hops.append({"hop": ttl, "ip": hop_ip, "rtt_ms": round((time.time() - pkt.sent_time) * 1000, 2)})
                    if hop_ip == host:
                        break
                else:
                    hops.append({"hop": ttl, "ip": "*", "rtt_ms": 0})
            except Exception:
                hops.append({"hop": ttl, "ip": "*", "rtt_ms": 0})
        # If every hop failed, fall back to system traceroute
        if hops and all(h["ip"] == "*" for h in hops):
            hops = []

    # Fall back to system traceroute (UDP on Linux, ICMP on macOS, ICMP on Windows)
    if not hops:
        try:
            res = subprocess.run(_traceroute_cmd(host, t), capture_output=True, text=True, timeout=t * max_hops)
            for line in res.stdout.split("\n"):
                m = TRACEROUTE_RE.match(line)
                if m:
                    ip_str = m.group(2) if m.group(2) != '*' else '*'
                    rtt = 0.0
                    if ip_str != '*':
                        rest = line[m.end():].strip()
                        rtt_m = re.search(r'([\d.]+)\s*ms', rest, re.IGNORECASE)
                        if rtt_m:
                            try:
                                rtt = round(float(rtt_m.group(1)), 2)
                            except ValueError:
                                pass
                    hops.append({"hop": int(m.group(1)), "ip": ip_str, "rtt_ms": rtt})
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    return hops


# ── Latency ─────────────────────────────────────────────────────────────
def measure_latency(host: str, timeout_val: Optional[float] = None) -> float:
    t = timeout_val or cfg().timeout
    try:
        start = time.time()
        with socket.create_connection((host, 80), timeout=t):
            return round((time.time() - start) * 1000, 2)
    except (socket.timeout, ConnectionRefusedError, OSError):
        try:
            start = time.time()
            ping_sweep(host, t)
            return round((time.time() - start) * 1000, 2)
        except Exception:
            return 0.0


# ── Banner / SSL / SSH ─────────────────────────────────────────────────
def banner_grab(host: str, port: int, timeout_val: Optional[float] = None) -> str:
    t = timeout_val or cfg().timeout
    banner = b""
    try:
        with socket.create_connection((host, port), timeout=t) as sock:
            time.sleep(0.3)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > BANNER_GRAB_MAX:
                    break
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    if not banner and port in (80, 8080, 443, 8443):
        try:
            with socket.create_connection((host, port), timeout=t) as sock:
                sock.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                time.sleep(0.3)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > BANNER_GRAB_MAX:
                        break
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return banner.decode("utf-8", errors="replace").strip() if banner else ""


def get_ssl_cert(host: str, port: int, timeout_val: Optional[float] = None) -> Dict[str, Any]:
    t = timeout_val or cfg().timeout
    cert_info: Dict[str, Any] = {}
    try:
        ctx = _get_ssl_ctx(warn=True)
        with socket.create_connection((host, port), timeout=t) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    try:
                        cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    except (ValueError, TypeError):
                        cert_info["subject"] = {}
                    try:
                        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    except (ValueError, TypeError):
                        cert_info["issuer"] = {}
                    cert_info["version"] = cert.get("version", "")
                    cert_info["serial"] = cert.get("serialNumber", "")
                    cert_info["notBefore"] = cert.get("notBefore", "")
                    cert_info["notAfter"] = cert.get("notAfter", "")
                    cert_info["subjectAltName"] = [x[1] for x in cert.get("subjectAltName", [])] if cert.get("subjectAltName") else []
                    cert_info["OCSP"] = cert.get("OCSP", [])
                    cert_info["caIssuers"] = cert.get("caIssuers", [])
                if HAS_CRYPTO:
                    try:
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            crt = x509.load_der_x509_certificate(der, default_backend())
                            cert_info["fingerprint_sha256"] = crt.fingerprint(hashes.SHA256()).hex()
                            cert_info["fingerprint_sha1"] = crt.fingerprint(hashes.SHA1()).hex()
                            if not cert:
                                try:
                                    cn = crt.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                                    org = crt.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                                    cert_info["subject"] = {}
                                    if cn: cert_info["subject"]["commonName"] = cn[0].value
                                    if org: cert_info["subject"]["organizationName"] = org[0].value
                                except Exception:
                                    cert_info["subject"] = {}
                                try:
                                    icn = crt.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                                    iorg = crt.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                                    cert_info["issuer"] = {}
                                    if icn: cert_info["issuer"]["commonName"] = icn[0].value
                                    if iorg: cert_info["issuer"]["organizationName"] = iorg[0].value
                                except Exception:
                                    cert_info["issuer"] = {}
                                cert_info["version"] = str(crt.version.value)
                                cert_info["serial"] = str(crt.serial_number)
                                cert_info["notBefore"] = str(crt.not_valid_before_utc)
                                cert_info["notAfter"] = str(crt.not_valid_after_utc)
                                try:
                                    san_ext = crt.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    cert_info["subjectAltName"] = [str(s.value) for s in san_ext.value]
                                except Exception:
                                    cert_info["subjectAltName"] = []
                    except Exception:
                        logger.debug("SSL fingerprint error on %s:%d", host, port)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("SSL connection error on %s:%d: %s", host, port, e)
    except Exception as e:
        logger.debug("SSL cert error on %s:%d: %s", host, port, e)
    return cert_info


def extract_ssh_key(host: str, port: int = 22, timeout_val: Optional[float] = None) -> str:
    t = timeout_val or cfg().timeout
    try:
        with socket.create_connection((host, port), timeout=t) as sock:
            return sock.recv(4096).decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""
    except Exception:
        return ""
