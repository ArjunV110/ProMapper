"""
Scan orchestrator — runs the full pipeline per host, called by CLI.
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from promapper.config import cfg, BANNER_VER_RE, SSL_PORTS, HAS_SCAPY, IS_TERMUX
from promapper.datatypes import HostResult, PortResult
from promapper.scanner import (
    resolve_host, reverse_dns, measure_latency, parse_ports, get_service_name,
    icmp_ping, ping_sweep, scan_single_port,
    idle_scan, banner_grab, get_ssl_cert, extract_ssh_key,
    traceroute, arp_discovery,
)
from promapper.detection import (
    guess_os, detect_http_tech, detect_waf, detect_cdn, detect_cloud,
    detect_honeypot, dir_brute_force, api_discovery, subdomain_enum,
    check_cves,
)
from promapper.lookup import geo_lookup, whois_lookup, shodan_query, lookup_mac_vendor
from promapper.brute import brute_force

logger = logging.getLogger(__name__)

if HAS_SCAPY:
    try:
        from scapy.all import Ether, ARP, sr1
    except ImportError:
        pass


def _stage_port_scan(
    ip: str, ports: List[int], scan_types: List[str],
    timeout_val: float, zombie: Optional[str],
) -> Tuple[List[PortResult], List[int], List[int]]:

    results: List[PortResult] = []
    open_tcp: List[int] = []
    open_udp: List[int] = []

    def process_port(port: int) -> PortResult:
        last_pr = PortResult(port=port, state="error")
        for stype in scan_types:
            if stype == "idle" and zombie:
                s = idle_scan(zombie, ip, port, timeout_val)
                last_pr.state = "open" if s is True else "closed" if s is False else "filtered"
                return last_pr
            pr = scan_single_port(ip, ip, port, stype, timeout_val)
            pr.state = pr.state if pr.state != "error" else "filtered"
            last_pr = pr
            if pr.state == "open" or (pr.state not in ("closed", "filtered") and stype == scan_types[-1]):
                return pr
        return last_pr

    thread_count = min(cfg().threads, 500)
    with ThreadPoolExecutor(max_workers=thread_count) as ex:
        fut_map = {ex.submit(process_port, p): p for p in ports}
        for f in as_completed(fut_map):
            p = fut_map[f]
            try:
                pr = f.result()
            except Exception as e:
                logger.debug("Port scan error on port %d: %s", p, e)
                continue
            results.append(pr)
            if pr.state == "open":
                if pr.protocol == "udp":
                    open_udp.append(pr.port)
                else:
                    open_tcp.append(pr.port)
    return results, open_tcp, open_udp


def _stage_enrich_ports(
    ip: str, ports: List[PortResult], args: argparse.Namespace, timeout_val: float,
) -> List[str]:
    host_cves: List[str] = []
    for pr in ports:
        pr.service = get_service_name(pr.port, pr.protocol)
        if pr.state != "open":
            continue
        if args.banner or args.service_version:
            if not pr.banner_grabbed and pr.protocol == "tcp":
                pr.banner = banner_grab(ip, pr.port, timeout_val)
                pr.banner_grabbed = True
                if pr.service in ("unknown", "") and pr.banner:
                    pr.service = pr.banner.split("\n")[0][:80]
        if args.service_version and pr.banner:
            m = BANNER_VER_RE.search(pr.banner)
            if m:
                pr.version = m.group(1)
        if args.ssl_cert and pr.port in SSL_PORTS:
            pr.ssl_cert = get_ssl_cert(ip, pr.port, timeout_val)
        if args.cve and (pr.service or pr.version):
            cves = check_cves(pr.service, pr.version or "")
            if cves:
                pr.cves = cves
                host_cves.extend(cves)
    return host_cves


def scan_host(entry: Tuple[str, str], args: argparse.Namespace) -> HostResult:
    original, target = entry
    result = HostResult(host=original)
    timeout_val = args.timeout if args.timeout else cfg().timeout

    # Stage 1: Resolve
    ip = resolve_host(target, cfg().dns_server)
    if not ip:
        logger.debug("Could not resolve %s", target)
        return result
    result.ip = ip
    result.reverse_dns = reverse_dns(ip)
    result.latency_ms = measure_latency(ip)

    # Stage 2: ARP (local)
    if HAS_SCAPY:
        try:
            ans = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1, verbose=0)
            if ans and ans.haslayer(ARP):
                result.mac = ans.getlayer(ARP).hwsrc
        except Exception:
            pass

    # Stage 3: Ping
    if args.ping_only:
        result.up = icmp_ping(ip) or ping_sweep(ip)
        if not result.up:
            return result

    # Stage 4: Port scan
    ports = parse_ports(args.ports)
    excl = parse_ports(args.exclude_ports) if args.exclude_ports else []
    ports = [p for p in ports if p not in excl] or [22, 80, 443, 8080]

    scan_types: List[str] = []
    if args.udp:
        scan_types.append("udp")
    for flag, stype in (
        ("syn", "syn"), ("fin", "fin"), ("null", "null"), ("xmas", "xmas"),
        ("ack", "ack"), ("window", "window"), ("maimon", "maimon"),
    ):
        if getattr(args, flag, False):
            scan_types.append(stype)
    if args.idle_scan:
        scan_types.append("idle")
    if not scan_types:
        scan_types.append("connect")

    zombie = args.idle_scan if args.idle_scan else None
    port_results, open_tcp, open_udp = _stage_port_scan(ip, ports, scan_types, timeout_val, zombie)
    result.ports = port_results
    result.open_tcp = open_tcp
    result.open_udp = open_udp

    # Stage 5: Enrich
    host_cves = _stage_enrich_ports(ip, port_results, args, timeout_val)
    result.cves = host_cves

    # Stage 5b: SSL cert (try on SSL ports even if scan reported filtered)
    if args.ssl_cert:
        for sp in sorted(p for p in SSL_PORTS if p in ports):
            if not any(pr.port == sp for pr in result.ports):
                cert_info = get_ssl_cert(ip, sp, timeout_val)
                if cert_info:
                    result.ports.append(PortResult(port=sp, state="open", protocol="tcp", service="https", ssl_cert=cert_info))
                    result.open_tcp.append(sp)

    # Stage 6: SSH key
    if args.ssh_key and 22 in result.open_tcp:
        ssh_banner = extract_ssh_key(ip, 22, timeout_val)
        if ssh_banner:
            found = False
            for pr in result.ports:
                if pr.port == 22:
                    pr.banner = ssh_banner
                    pr.banner_grabbed = True
                    found = True
                    break
            if not found:
                result.ports.append(PortResult(port=22, state="open", service="SSH", banner=ssh_banner, banner_grabbed=True))
                result.open_tcp.append(22)

    # Stage 7: HTTP tech
    if args.http_tech:
        for prt in (443, 8443, 80, 8080):
            if prt in result.open_tcp:
                result.http_tech = detect_http_tech(ip, prt)
                if result.http_tech:
                    break

    # Stage 8: WAF
    if args.detect_waf:
        for prt in (443, 80):
            if prt in result.open_tcp:
                result.waf = detect_waf(ip, prt)
                if result.waf:
                    break

    # Stage 9: CDN / Cloud
    if args.detect_cdn:
        result.cdn = detect_cdn(ip)
    if args.detect_cloud:
        result.cloud = detect_cloud(ip)

    # Stage 10: Honeypot
    if args.detect_honeypot:
        for pr in result.ports:
            if pr.banner:
                hp = detect_honeypot(ip, pr.port, pr.banner)
                if hp:
                    result.honeypot = hp
                    break

    # Stage 11: OS guess
    if args.os_guess:
        os_result = guess_os(ip, timeout_val)
        result.os_guess = os_result["name"]
        result.os_accuracy = os_result["accuracy"]

    # Stage 12: Traceroute
    if args.traceroute:
        result.traceroute = traceroute(ip, timeout_val=timeout_val)

    # Stage 13: Geo / ASN
    if args.geo:
        result.geo = geo_lookup(ip)
        if result.geo:
            result.asn = result.geo.get("asn", "")
            result.org = result.org or result.geo.get("org", "")
            result.isp = result.isp or result.geo.get("isp", "")
    if args.asn and not result.geo and not result.asn:
        geo = geo_lookup(ip)
        result.asn = geo.get("asn", "")
        result.isp = geo.get("isp", "")
        result.org = geo.get("org", "")

    # Stage 14: WHOIS
    if args.whois:
        result.whois = whois_lookup(ip)

    # Stage 15: Shodan
    if args.shodan:
        result.shodan = shodan_query(ip)

    # Stage 16: Dir bust
    if args.dir_bust is not None:
        for prt in (443, 80, 8080, 8443):
            if prt in result.open_tcp:
                result.http_dirs = dir_brute_force(ip, prt, args.dir_bust or None, timeout_val)
                break

    # Stage 17: API discovery
    if args.api_discovery:
        for prt in (443, 80, 8080):
            if prt in result.open_tcp:
                result.api_endpoints = api_discovery(ip, prt, timeout_val)
                break

    # Stage 18: Subdomain enum
    if args.subdomain_enum is not None and result.reverse_dns:
        domain = ".".join(result.reverse_dns.split(".")[-2:])
        result.subdomains = subdomain_enum(domain, args.subdomain_enum or None, timeout_val)

    # Stage 19: MAC vendor
    if args.mac_vendor and result.mac:
        result.mac_vendor = lookup_mac_vendor(result.mac)

    # Stage 20: Brute force
    if args.brute:
        services = [s.strip().lower() for s in args.brute.split(",")]
        port_map = {"ssh": 22, "ftp": 21, "http": 80, "telnet": 23}
        users: List[str] = [args.user] if args.user else []
        passwords: List[str] = []
        if args.user_list and os.path.isfile(args.user_list):
            try:
                with open(args.user_list, errors="replace") as f:
                    users = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.debug("Userlist error: %s", e)
        if not users:
            users = ["admin", "root", "user", "test"]
        if args.password_list and os.path.isfile(args.password_list):
            try:
                with open(args.password_list, errors="replace") as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.debug("Passlist error: %s", e)
        if not passwords:
            passwords = ["admin", "password", "123456", "root", "test"]
        for svc in services:
            if svc in port_map and port_map[svc] in result.open_tcp:
                logger.info("Brute forcing %s on %s:%d", svc, ip, port_map[svc])
                result.brute_creds.extend(brute_force(ip, port_map[svc], svc, users, passwords, timeout_val))

    # Stage 21: Determine if host is up
    # A host is "up" if we got a definitive response on any port:
    # - "open" or "closed" means we received a response (TCP SYN/ACK, RST, or ICMP unreachable)
    # - "open|filtered" alone is ambiguous - no response received
    if any(pr.state in ("open", "closed", "unfiltered") for pr in port_results):
        result.up = True
    elif icmp_ping(ip) or ping_sweep(ip):
        result.up = True
    elif result.mac:
        result.up = True

    return result
