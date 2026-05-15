"""
Core scanning engine — DNS resolution, port scanning, ping, traceroute, banner/SSL.
"""
from __future__ import annotations

import datetime
import hashlib
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

from nmapclone.config import (
    SSL_PORTS, MAX_CIDR_HOSTS, BANNER_GRAB_MAX,
    IS_WINDOWS, IS_MACOS, IS_TERMUX, HAS_SCAPY, HAS_DNS, HAS_CRYPTO,
    ScanConfig, cfg, _get_ssl_ctx,
    TTL_RE, TRACEROUTE_RE, BANNER_VER_RE,
)
from nmapclone.datatypes import PortResult, HostResult

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
        return socket.getservbyport(port, proto)
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
            hosts = list(net.hosts())
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
    if source_port:
        try:
            sock.bind(("0.0.0.0", source_port))
        except OSError:
            logger.debug("source_port bind(%d) failed", source_port)
    return sock


def tcp_connect_scan(host: str, port: int, timeout_val: Optional[float] = None,
                     source_port: Optional[int] = None) -> bool:
    sock = None
    try:
        sock = make_sock(timeout_val, source_port)
        sock.connect((host, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def udp_scan(host: str, port: int, timeout_val: Optional[float] = None) -> bool:
    t = timeout_val or cfg().timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(t)
        sock.sendto(b"\x00" * 8, (host, port))
        try:
            sock.recvfrom(1024)
            return True
        except (socket.timeout, OSError):
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except OSError:
        return False


# ── Scapy-based scans ───────────────────────────────────────────────────
def syn_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        logger.debug("SYN scan needs scapy, falling back to connect")
        return tcp_connect_scan(host, port, timeout_val)
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="S"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return None
        if ans.haslayer(TCP):
            flags = ans.getlayer(TCP).flags
            if flags == 0x12:
                return True
            if flags == 0x14:
                return False
        return None
    except Exception as e:
        logger.debug("SYN scan error: %s", e)
        return None


def fin_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="F"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x14:
            return False
    except Exception:
        pass
    return None


def null_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags=""),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x14:
            return False
    except Exception:
        pass
    return None


def xmas_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="FPU"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x14:
            return False
    except Exception:
        pass
    return None


def ack_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="A"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x14:
            return True
    except Exception:
        pass
    return False


def window_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="A"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans and ans.haslayer(TCP):
            return ans.getlayer(TCP).window > 0
    except Exception:
        pass
    return False


def maimon_scan(host: str, port: int, timeout_val: Optional[float] = None) -> Optional[bool]:
    if not HAS_SCAPY:
        return None
    try:
        ans = sr1(IP(dst=host) / TCP(dport=port, flags="FP"),
                  timeout=timeout_val or cfg().timeout, verbose=0)
        if ans is None:
            return True
        if ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x14:
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
            ans = sr1(IP(dst=host) / TCP(dport=445, flags="SA"),
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
        sr(IP(src=zombie, dst=target) / TCP(dport=port, flags="S"),
           timeout=timeout_val or cfg().timeout, verbose=0)
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
        result.state = "open" if udp_scan(ip, port, timeout_val) else "closed"
        return result
    if scan_type == "connect":
        result.state = "open" if tcp_connect_scan(ip, port, timeout_val) else "closed"
        return result
    if scan_type == "idle":
        return result
    func = SCAN_FUNCS.get(scan_type)
    if func is None:
        result.state = "error"
        return result
    s = func(ip, port, timeout_val)
    if scan_type in ("fin", "null", "xmas", "maimon"):
        result.state = "open|filtered" if s else "closed" if s is False else "error"
    elif scan_type == "ack":
        result.state = "unfiltered" if s else "filtered"
    elif scan_type == "window":
        result.state = "open" if s else "closed"
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
    if HAS_SCAPY and not IS_TERMUX:
        try:
            ans = sr1(IP(dst=host) / ICMP(),
                      timeout=timeout_val or cfg().timeout, verbose=0)
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
    if HAS_SCAPY and not IS_TERMUX:
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
    else:
        try:
            res = subprocess.run(_traceroute_cmd(host, t), capture_output=True, text=True, timeout=t * max_hops)
            for line in res.stdout.split("\n"):
                m = TRACEROUTE_RE.match(line)
                if m:
                    ip_str = m.group(2) if m.group(2) != '*' else '*'
                    hops.append({"hop": int(m.group(1)), "ip": ip_str, "rtt_ms": 0})
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
                            cert_info["fingerprint_sha256"] = crt.fingerprint(hashlib.sha256).hex()
                            cert_info["fingerprint_sha1"] = crt.fingerprint(hashlib.sha1).hex()
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
