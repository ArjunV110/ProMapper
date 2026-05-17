"""
Command-line interface — argument parser, main entry point, orchestration.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from promapper import __version__
from promapper.config import (
    ScanConfig, cfg, cfg_set, configure_logging,
    MAX_GLOBAL_THREADS, BANNER_ART, IS_WINDOWS, IS_TERMUX, HAS_SCAPY,
    INVALID_PATH, _is_valid_target,
)
from promapper.datatypes import HostResult
from promapper.orchestrator import scan_host
from promapper.scanner import expand_targets, arp_discovery, parse_ports
from promapper.lookup import lookup_mac_vendor
from promapper.formatters import (
    fmt_terminal, fmt_termux, fmt_json, fmt_xml, fmt_csv, fmt_grepable, fmt_html,
)

# Auto-select formatter: simple for narrow terminals, box for wide
import shutil
_term_width = shutil.get_terminal_size().columns
if IS_TERMUX or _term_width < 74:
    _fmt = fmt_termux
else:
    _fmt = fmt_terminal
from promapper.state import load_state, save_state, diff_results, send_notification

logger = logging.getLogger(__name__)

_HANDLE_SCAN_LOCK: threading.Lock = threading.Lock()
_shutdown_requested: bool = False


def _signal_handler(signum: int, frame) -> None:
    global _shutdown_requested
    if _shutdown_requested:
        print("\n[!] Force exit", file=sys.stderr)
        sys.exit(130)
    _shutdown_requested = True
    print("\n[!] Shutdown requested — finishing current scan...", file=sys.stderr)


def _validate_path(p: str) -> bool:
    if not p or not isinstance(p, str):
        return False
    return not bool(INVALID_PATH.search(os.path.normpath(p)))


def _parse_targets(args: argparse.Namespace) -> List[str]:
    targets: set = set()
    file_loaded: str | None = None
    for t in args.target:
        if os.path.isfile(t) and file_loaded != t:
            if not _validate_path(t):
                logger.error("Invalid target file path: %s", t)
                continue
            try:
                with open(t, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and _is_valid_target(line):
                            targets.add(line)
                file_loaded = t
            except Exception as e:
                logger.error("Error reading target file: %s", e)
        else:
            if _is_valid_target(t):
                targets.add(t)
            else:
                logger.error("Invalid target skipped: %s", t)
    if args.input_file and file_loaded != args.input_file:
        if not _validate_path(args.input_file):
            logger.error("Invalid input file path: %s", args.input_file)
        else:
            try:
                with open(args.input_file, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and _is_valid_target(line):
                            targets.add(line)
            except Exception as e:
                logger.error("Error reading input file: %s", e)
    return list(targets)


def _run_scan_pass(expanded: List[Tuple[str, str]], args: argparse.Namespace,
                   results: List[HostResult]) -> float:
    start = time.time()
    host_threads = min(cfg().threads, max(1, len(expanded)), MAX_GLOBAL_THREADS)
    is_batch = any([args.output_json, args.output_xml, args.html])
    with ThreadPoolExecutor(max_workers=host_threads) as ex:
        fut_map = {ex.submit(scan_host, e, args): e for e in expanded}
        for f in as_completed(fut_map):
            if _shutdown_requested:
                break
            try:
                res = f.result()
            except Exception as e:
                logger.debug("Host scan error: %s", e)
                continue
            results.append(res)
            if res.up and not is_batch:
                tags = "".join(f" {k}:{v}" for k, v in [
                    ("OS", res.os_guess), ("CDN", res.cdn), ("WAF", res.waf),
                ] if v)
                if res.geo and res.geo.get("country"):
                    tags += f" [{res.geo['country']}]"
                open_count = sum(1 for p in res.ports if p.state == "open")
                total = len(res.ports)
                print(f"  {res.host:<20} {res.ip:<15} {open_count}/{total} open ports{tags}")
    return time.time() - start


def _write_outputs(results: List[HostResult], args: argparse.Namespace,
                   output_text: str) -> None:
    outputs = [
        (args.output_normal, output_text),
        (args.output_json, fmt_json(results)),
        (args.output_xml, fmt_xml(results)),
        (args.output_csv, fmt_csv(results)),
        (args.output_grepable, fmt_grepable(results)),
        (args.html, fmt_html(results)),
    ]
    for fpath, content in outputs:
        if fpath:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="promapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="PRO Network Mapper — cross-platform",
        epilog="""Examples:
  promapper scanme.nmap.org
""",
    )
    p.add_argument("-V", "--version", action="version", version=f"promapper {__version__}",
                   help="Show version and exit")

    g_target = p.add_argument_group("Target Specification")
    g_target.add_argument("target", nargs="*", help="Host(s), CIDR, or file")
    g_target.add_argument("-iL", "--input-file", help="Read targets from file")
    g_target.add_argument("-p", "--ports", default="22,80,443,8080", help="Ports (22,80 or 1-1024)")
    g_target.add_argument("--exclude-ports", help="Ports to exclude")

    g_scan = p.add_argument_group("Scan Techniques")
    g_scan.add_argument("-sU", "--udp", action="store_true", help="UDP scan")
    g_scan.add_argument("-sS", "--syn", action="store_true", help="TCP SYN stealth scan (needs scapy)")
    g_scan.add_argument("-sF", "--fin", action="store_true", help="TCP FIN scan (needs scapy)")
    g_scan.add_argument("-sN", "--null", action="store_true", help="TCP Null scan (needs scapy)")
    g_scan.add_argument("-sX", "--xmas", action="store_true", help="TCP Xmas scan (needs scapy)")
    g_scan.add_argument("-sA", "--ack", action="store_true", help="TCP ACK scan (needs scapy)")
    g_scan.add_argument("-sW", "--window", action="store_true", help="TCP Window scan (needs scapy)")
    g_scan.add_argument("-sM", "--maimon", action="store_true", help="TCP Maimon scan (needs scapy)")
    g_scan.add_argument("--idle-scan", metavar="ZOMBIE", help="Idle scan via zombie host")
    g_scan.add_argument("--source-port", type=int, help="Source port for scans")
    g_scan.add_argument("--badsum", action="store_true", help="Send bad checksums")
    g_scan.add_argument("-sL", "--list-scan", action="store_true", help="List targets only")
    g_scan.add_argument("-sn", "--ping-only", action="store_true", help="Ping sweep only")
    g_scan.add_argument("-PR", "--arp-discovery", action="store_true", help="ARP discovery (local)")

    g_detect = p.add_argument_group("Detection & Enumeration")
    g_detect.add_argument("-sV", "--service-version", action="store_true", help="Service version detection")
    g_detect.add_argument("-O", "--os-guess", action="store_true", help="OS fingerprinting")
    g_detect.add_argument("--traceroute", action="store_true", help="Traceroute to target")
    g_detect.add_argument("--banner", action="store_true", help="Banner grabbing")
    g_detect.add_argument("--ssl-cert", action="store_true", help="SSL/TLS certificate inspection")
    g_detect.add_argument("--http-tech", action="store_true", help="HTTP technology detection")
    g_detect.add_argument("--dir-bust", nargs="?", const="", help="Directory brute-force (wordlist path)")
    g_detect.add_argument("--subdomain-enum", nargs="?", const="", help="Subdomain enumeration (wordlist path)")
    g_detect.add_argument("--api-discovery", action="store_true", help="API endpoint discovery")
    g_detect.add_argument("--brute", help="Services to brute (ssh,ftp,http,telnet)")
    g_detect.add_argument("-u", "--user", help="Username for brute force")
    g_detect.add_argument("-P", "--password-list", help="Password wordlist for brute force")
    g_detect.add_argument("--user-list", help="Username wordlist for brute force")
    g_detect.add_argument("--ssh-key", action="store_true", help="Extract SSH host key")
    g_detect.add_argument("--detect-waf", action="store_true", help="WAF detection")
    g_detect.add_argument("--detect-cdn", action="store_true", help="CDN detection")
    g_detect.add_argument("--detect-cloud", action="store_true", help="Cloud provider detection")
    g_detect.add_argument("--detect-honeypot", action="store_true", help="Honeypot detection")

    g_info = p.add_argument_group("Information Gathering")
    g_info.add_argument("--geo", action="store_true", help="Geolocation lookup")
    g_info.add_argument("--asn", action="store_true", help="ASN/ISP/ORG lookup")
    g_info.add_argument("--whois", action="store_true", help="WHOIS lookup")
    g_info.add_argument("--shodan", action="store_true", help="Shodan query (set SHODAN_API_KEY)")
    g_info.add_argument("--cve", action="store_true", help="Check known CVEs for services")
    g_info.add_argument("--mac-vendor", action="store_true", help="MAC vendor lookup")

    g_output = p.add_argument_group("Output")
    g_output.add_argument("-oN", "--output-normal", help="Output to file (normal)")
    g_output.add_argument("-oX", "--output-xml", help="XML output")
    g_output.add_argument("-oJ", "--output-json", help="JSON output")
    g_output.add_argument("-oG", "--output-grepable", help="Grepable output")
    g_output.add_argument("-oC", "--output-csv", help="CSV output")
    g_output.add_argument("--html", help="HTML report")
    g_output.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    g_output.add_argument("--open", action="store_true", help="Show only open ports")

    g_perf = p.add_argument_group("Performance & Timing")
    g_perf.add_argument("-T", "--timing", type=int, choices=range(0, 6), default=3,
                        help="Timing template 0-5 (paranoid=0, insane=5)")
    g_perf.add_argument("--threads", type=int, default=100, help="Max threads")
    g_perf.add_argument("--rate-limit", type=int, help="Packets per second")
    g_perf.add_argument("--random-delay", help="Random delay min,max (e.g. 0.1,1.0)")
    g_perf.add_argument("--timeout", type=float, default=2.0, help="Socket timeout")
    g_perf.add_argument("--fragment", action="store_true", help="Fragment packets (needs scapy)")
    g_perf.add_argument("--ttl", type=int, help="Set IP TTL")

    g_adv = p.add_argument_group("Advanced & Monitoring")
    g_adv.add_argument("-D", "--decoy", help="Decoy IPs (comma-separated)")
    g_adv.add_argument("--proxy", help="Proxy (socks5://user:pass@host:port)")
    g_adv.add_argument("--dns-server", help="Custom DNS server")
    g_adv.add_argument("--continuous", nargs="?", type=int, const=60, metavar="SECONDS",
                       help="Continuous monitoring mode (default: 60s)")
    g_adv.add_argument("--diff", action="store_true", help="Diff mode (changes only)")
    g_adv.add_argument("--notify", action="store_true", help="Notify on changes")
    g_adv.add_argument("--interactive", action="store_true", help="Interactive mode")
    g_adv.add_argument("--update", action="store_true", help="Update PROMAPPER to latest version via git")
    return p


def main() -> None:
    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _signal_handler)

    parser = _build_parser()
    args = parser.parse_args()

    config = ScanConfig.from_args(args)
    cfg_set(config)
    configure_logging(verbose=args.verbose)

    if args.update:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)
        git_dir = os.path.join(project_dir, ".git")
        if os.path.isdir(git_dir):
            print("[*] Updating PROMAPPER from GitHub...")
            try:
                res = subprocess.run(
                    ["git", "-C", project_dir, "pull", "--no-rebase"],
                    capture_output=True, text=True, timeout=30,
                )
                if res.returncode == 0:
                    msg = res.stdout.strip().split("\n")[-1]
                    print(f"  {msg}")
                    print("[*] Update complete. Restart to use the latest version.")
                else:
                    print(f"[!] Update failed: {res.stderr.strip()}")
            except FileNotFoundError:
                print("[!] Git is not installed. Install git or update manually:")
                print("    git pull")
            except subprocess.TimeoutExpired:
                print("[!] Update timed out. Check your internet connection.")
        else:
            print("[!] Not a git repository. Clone the repo first:")
            print("    git clone https://github.com/ArjunV110/ProMapper.git")
        sys.exit(0)

    raw_targets = _parse_targets(args)
    if not raw_targets:
        logger.error("No targets specified")
        sys.exit(1)

    expanded = expand_targets(raw_targets)

    if args.list_scan:
        print("Targets:")
        for orig, ip in expanded:
            print(f"  {orig:<20} -> {ip}")
        sys.exit(0)

    if args.arp_discovery:
        arp_results: List[HostResult] = []
        for t in raw_targets:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                net = None
            if net:
                for ip, mac in arp_discovery(str(net)):
                    r = HostResult(host=ip, ip=ip, mac=mac, up=True)
                    r.mac_vendor = lookup_mac_vendor(mac)
                    arp_results.append(r)
        if not arp_results:
            logger.error("No hosts discovered via ARP")
        else:
            print(_fmt(arp_results, args))
        sys.exit(0)

    scapy_flags = {
        "syn": "-sS/--syn", "fin": "-sF/--fin", "null": "-sN/--null",
        "xmas": "-sX/--xmas", "ack": "-sA/--ack", "window": "-sW/--window",
        "maimon": "-sM/--maimon",
    }
    active_scapy = [name for flag, name in scapy_flags.items() if getattr(args, flag, False)]
    if active_scapy and not IS_WINDOWS and not IS_TERMUX and os.geteuid() != 0:
        print(f"[!] Warning: {'/'.join(active_scapy)} require{'s' if len(active_scapy) == 1 else ''} root (sudo) for raw packets — falling back to connect() scan")

    is_batch = any([args.output_json, args.output_xml, args.html])
    if not is_batch:
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(BANNER_ART)
        print(f"[*] Platform:     {sys.platform}")
        print(f"[*] Targets:      {len(expanded)}")
        print(f"[*] Ports:        {args.ports}")
        print(f"[*] Threads:      {cfg().threads}")
        print(f"[*] Timeout:      {cfg().timeout}s")
        print(f"[*] Started:      {ts}")
        print()

    results: List[HostResult] = []
    run_count = 0
    max_runs = 1 if not args.continuous else 999999

    while run_count < max_runs:
        if _shutdown_requested:
            break
        run_count += 1
        if args.continuous and run_count > 1:
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[*] Continuous scan #{run_count} — {ts}")

        with _HANDLE_SCAN_LOCK:
            results.clear()
            elapsed = _run_scan_pass(expanded, args, results)

        if _shutdown_requested:
            break

        if not is_batch:
            up_count = sum(1 for r in results if r.up)
            print(f"\n[*] Scan finished in {elapsed:.1f}s — {up_count}/{len(results)} hosts up")

        if args.diff or args.continuous:
            old_state = load_state()
            changes = diff_results(old_state, results)
            if changes:
                print("\n[*] Changes detected:")
                for c in changes:
                    print(f"    {c}")
                if args.notify:
                    send_notification("promapper", f"{len(changes)} change(s) detected")
            save_state(results)

        output_text = _fmt(results, args)
        _write_outputs(results, args, output_text)

        if not args.continuous:
            print(output_text)

        if args.continuous and run_count < max_runs:
            interval = args.continuous if isinstance(args.continuous, int) else 60
            print(f"[*] Waiting {interval}s for next scan...")
            try:
                for _ in range(interval):
                    if _shutdown_requested:
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                break

    if args.interactive:
        print("\n[*] Interactive mode (type 'help' for commands)")
        import code
        code.interact(local=locals())


if __name__ == "__main__":
    main()
