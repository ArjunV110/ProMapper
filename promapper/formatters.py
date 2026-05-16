"""
Output formatters — terminal, JSON, XML, CSV, grepable, HTML.
All user-facing values are escaped to prevent injection.
"""
from __future__ import annotations

import csv
import datetime
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

from promapper.config import BOX_WIDTH, _supports_color, BANNER_ART
from promapper.datatypes import HostResult, PortResult

_ansi_strip: re.Pattern = re.compile(r'\033\[[0-9;]*m')
_CONTROL_CHARS: re.Pattern = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_MULTI_SPACE: re.Pattern = re.compile(r'  +')


def _sanitize_text(text: str, max_len: int = 200) -> str:
    """Sanitize text for safe display inside box-drawn tables.
    
    - Strips ANSI escape codes (already present from color functions)
    - Removes control characters (keeps \\n, \\r, \\t)
    - Replaces newlines with visible \\n representation
    - Collapses multiple spaces
    - Truncates to max_len
    """
    s = str(text)
    s = s.replace('\r\n', '\\n').replace('\r', '\\n').replace('\n', '\\n')
    s = _CONTROL_CHARS.sub('', s)
    s = _MULTI_SPACE.sub(' ', s)
    if len(s) > max_len:
        s = s[:max_len - 3] + '...'
    return s.strip()


def _vis_len(s: str) -> int:
    return len(_ansi_strip.sub('', str(s)))


def _escape_cell(text: str) -> str:
    """Prevent CSV formula injection (OWASP)."""
    if not text:
        return ""
    if text[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + text
    return text


def _escape_html(text: str) -> str:
    t = str(text)
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def _escape_xml(text: str) -> str:
    t = str(text)
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def _bx(s: str, w: int = BOX_WIDTH) -> str:
    pad = max(0, w - 2 - _vis_len(s))
    return f"  │ {s}{' ' * pad} │"


# ── Terminal Formatter ───────────────────────────────────────────────────
def fmt_terminal(results: List[HostResult], args) -> str:
    lines: List[str] = [BANNER_ART]
    has_color = _supports_color()
    _grn = lambda s: f"\033[92m{s}\033[0m" if has_color else s
    _cya = lambda s: f"\033[96m{s}\033[0m" if has_color else s
    _yel = lambda s: f"\033[93m{s}\033[0m" if has_color else s
    _red = lambda s: f"\033[91m{s}\033[0m" if has_color else s
    _bld = lambda s: f"\033[1m{s}\033[0m" if has_color else s

    W = BOX_WIDTH
    lines.append(f"  {_bld('SCAN REPORT')}")
    lines.append(f"  {_bld('Started')}:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  {_bld('Targets')}:   {len(results)} host(s)")
    lines.append(f"  {'═' * 72}")
    lines.append("")

    for idx, res in enumerate(results, 1):
        if not res.up:
            lines.append(f"  {'╭' + '─' * W + '╮'}")
            lines.append(_bx(f" {_red('●')} HOST #{idx}: {_sanitize_text(res.host, 28):<28} {_red('(down / unresolved)')}", W))
            lines.append(f"  {'╰' + '─' * W + '╯'}")
            lines.append("")
            continue

        tags = [f"OS:{res.os_guess}"] if res.os_guess else []
        if res.cdn:
            tags.append(f"CDN:{res.cdn}")
        if res.cloud:
            tags.append(f"Cloud:{res.cloud}")
        if res.waf:
            tags.append(f"WAF:{res.waf}")
        tag_str = f"  [{', '.join(tags)}]" if tags else ""

        # If tags are too long, move them to a separate line
        header_line = f" {_grn('●')} {_bld(_sanitize_text(res.host, 28)):<28} {res.ip:<16} {res.latency_ms:>6.1f}ms"
        if tag_str and _vis_len(header_line + tag_str) > (W - 2 - 2):
            main_line_pad = max(0, W - 2 - _vis_len(header_line))
            lines.append(f"  {'╭' + '─' * W + '╮'}")
            lines.append(f"  │ {header_line}{' ' * main_line_pad} │")
            lines.append(_bx(f"  {_sanitize_text(tag_str.strip(), 60)}", W))
        else:
            lines.append(f"  {'╭' + '─' * W + '╮'}")
            lines.append(_bx(header_line + tag_str, W))
        if res.reverse_dns:
            lines.append(_bx(f"    DNS: {_sanitize_text(res.reverse_dns, 50)}", W))
        if res.mac:
            lines.append(_bx(f"    MAC: {_sanitize_text(res.mac, 17)}  ({_sanitize_text(res.mac_vendor, 20)})", W))
        lines.append(f"  {'╰' + '─' * W + '╯'}")
        lines.append("")

        # ── Host Overview ──────────────────────────────────────────────
        _title = 'Host Overview'
        lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
        ov: List[Tuple[str, str]] = [("Hostname", res.host), ("IP Address", res.ip)]
        if res.reverse_dns:
            ov.append(("Reverse DNS", res.reverse_dns))
        if res.mac:
            ov.append(("MAC Address", f"{res.mac}  ({res.mac_vendor})"))
        ov.append(("Latency", f"{res.latency_ms:.1f} ms"))
        if res.os_guess:
            ov.append(("OS Guess", f"{res.os_guess} (acc: {res.os_accuracy:.0f}%)"))
        for k in ("cdn", "cloud", "waf", "honeypot"):
            v = getattr(res, k, "")
            if v:
                ov.append((k.title(), v))
        for label, val in ov:
            lines.append(_bx(f"{label:<20} {_sanitize_text(str(val), 44)}", W))
        lines.append(f"  └{'─' * W}┘")
        lines.append("")

        # ── Open Ports ─────────────────────────────────────────────────
        if res.ports:
            _title = 'Open Ports'
            lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
            hdr = f"{'PORT':<7} {'PROTO':<6} {'STATE':<13} {'SERVICE':<22} {'VERSION':<16}"
            sep = f"{'─' * 4:<7} {'─' * 5:<6} {'─' * 10:<13} {'─' * 20:<22} {'─' * 14:<16}"
            lines.append(_bx(hdr, W))
            lines.append(_bx(sep, W))
            for pr in sorted(res.ports, key=lambda x: x.port):
                if args.open and pr.state != "open":
                    continue
                st = _grn(pr.state) if pr.state == "open" else _yel(pr.state)
                sv = _sanitize_text(pr.service or "", 22)[:22]
                vr = _sanitize_text(pr.version or "", 16)[:16]
                # Pad each column manually using visible length (ANSI codes are invisible)
                col_port = f"{pr.port:<7}"
                col_proto = f"{pr.protocol.upper():<6}"
                st_vis = _vis_len(st)
                col_state = f"{st}{' ' * max(0, 13 - st_vis)}"
                col_svc = f"{sv:<22}"
                col_ver = f"{vr:<16}"
                lines.append(_bx(f"{col_port} {col_proto} {col_state} {col_svc} {col_ver}", W))
            lines.append(f"  └{'─' * W}┘")

            # Banners and SSL certs displayed below the box as plain text
            for pr in sorted(res.ports, key=lambda x: x.port):
                if args.open and pr.state != "open":
                    continue
                if pr.banner and args.banner:
                    banner_text = _sanitize_text(pr.banner, 200)
                    lines.append(f"    {_cya('Banner')} ({pr.port}/{pr.protocol}): {banner_text}")
                if pr.ssl_cert and args.ssl_cert:
                    cn = _sanitize_text(pr.ssl_cert.get("subject", {}).get("commonName", "") or pr.ssl_cert.get("subject", {}).get("CN") or "", 40)
                    exp = _sanitize_text(pr.ssl_cert.get("notAfter", "") or "", 20)
                    lines.append(f"    {_cya('SSL')} ({pr.port}/{pr.protocol}): {cn}  (exp: {exp})")
            lines.append("")

        # ── Web Analysis ────────────────────────────────────────────────
        if res.http_tech or res.http_dirs or res.api_endpoints or res.subdomains:
            _title = 'Web Analysis'
            lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
            if res.http_tech:
                lines.append(_bx(f"{_cya('Technologies')}:", W))
                for name, cat in res.http_tech.items():
                    lines.append(_bx(f"  {_sanitize_text(name, 30):<30} {_sanitize_text(cat, 30)}", W))
            if res.http_dirs:
                lines.append(_bx(f"{_cya('Discovered Paths')}:", W))
                lines.append(_bx(f"  {'STATUS':<8} {'PATH'}", W))
                lines.append(_bx(f"  {'─' * 6:<8} {'─' * 40}", W))
                for d in res.http_dirs[:25]:
                    sc = _grn(str(d["status"])) if d["status"] == 200 else _yel(str(d["status"]))
                    lines.append(_bx(f"  {sc:<8} {_sanitize_text(d['path'], 40)}", W))
            if res.api_endpoints:
                lines.append(_bx(f"{_cya('API Endpoints')}:", W))
                lines.append(_bx(f"  {'STATUS':<8} {'PATH':<30} {'TYPE'}", W))
                lines.append(_bx(f"  {'─' * 6:<8} {'─' * 30} {'─' * 10}", W))
                for ep in res.api_endpoints:
                    j = _cya('(JSON)') if ep['json'] else ''
                    lines.append(_bx(f"  {ep['status']:<8} {_sanitize_text(ep['path'], 30):<30} {j}", W))
            if res.subdomains:
                lines.append(_bx(f"{_cya('Subdomains')}:", W))
                for sd in res.subdomains[:15]:
                    lines.append(_bx(f"  {_sanitize_text(sd['subdomain'], 40):<40} {_sanitize_text(sd['ip'], 15)}", W))
            lines.append(f"  └{'─' * W}┘")
            lines.append("")

        # ── Traceroute ──────────────────────────────────────────────────
        if res.traceroute:
            _title = 'Traceroute'
            lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
            tr_hdr = f"{'HOP':<5} {'IP ADDRESS':<21} {'RTT':<10}"
            tr_sep = f"{'─' * 4:<5} {'─' * 20:<21} {'─' * 9:<10}"
            lines.append(_bx(tr_hdr, W))
            lines.append(_bx(tr_sep, W))
            for hop in res.traceroute[:15]:
                ip_s = hop['ip'] if hop['ip'] != '*' else _cya('*')
                rtt_s = f"{hop['rtt_ms']:.1f}ms" if hop['rtt_ms'] else _cya('*')
                lines.append(_bx(f"{hop['hop']:<5} {ip_s:<21} {rtt_s:<10}", W))
            lines.append(f"  └{'─' * W}┘")
            lines.append("")

        # ── Network Intelligence ────────────────────────────────────────
        if res.geo or res.asn or res.shodan or res.whois:
            _title = 'Network Intelligence'
            lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
            if res.geo:
                gd = res.geo
                loc = f"{gd.get('city', '')}, {gd.get('region', '')}, {gd.get('country', '')}"
                lines.append(_bx(f"{_cya('Location')}:     {_sanitize_text(loc, 50)}", W))
                if gd.get('lat') is not None:
                    lines.append(_bx(f"{_cya('Coordinates')}: {gd['lat']}, {gd['lon']}", W))
            if res.asn:
                lines.append(_bx(f"{_cya('ASN/ISP')}:     {_sanitize_text(str(res.asn), 13)}  ({_sanitize_text(res.isp, 28)})", W))
            if res.shodan and res.shodan.get("ports"):
                lines.append(_bx(f"{_cya('Shodan Ports')}: {_sanitize_text(', '.join(map(str, res.shodan['ports'])), 50)}", W))
                if res.shodan.get("tags"):
                    lines.append(_bx(f"{_cya('Shodan Tags')}:  {_sanitize_text(', '.join(res.shodan['tags']), 50)}", W))
            if res.whois:
                for wl in res.whois.split("\n")[:8]:
                    lines.append(_bx(f"  {_sanitize_text(wl, 64)}", W))
            lines.append(f"  └{'─' * W}┘")
            lines.append("")

        # ── Security Findings ───────────────────────────────────────────
        if res.cves or res.brute_creds:
            _title = 'Security Findings'
            lines.append(f"  ┌─ {_bld(_title)} " + f"{'─' * (W - 3 - len(_title))}┐")
            if res.cves:
                lines.append(_bx(f"{_red('CVEs')} ({len(res.cves)} found):", W))
                for cve in sorted(set(res.cves)):
                    lines.append(_bx(f"  {_red(cve)}", W))
            if res.brute_creds:
                lines.append(_bx(f"{_red('Cracked Credentials')}:", W))
                for cred in res.brute_creds:
                    lines.append(_bx(f"  {_sanitize_text(cred['user'], 30)}:{_sanitize_text(cred['password'], 30)}", W))
            lines.append(f"  └{'─' * W}┘")
            lines.append("")

        if idx < len(results):
            lines.append(f"  {'─' * 72}")
            lines.append("")

    lines.append(f"  {'═' * 72}")
    up_count = sum(1 for r in results if r.up)
    lines.append(f"  {_bld('SCAN COMPLETE')}: {up_count}/{len(results)} hosts up  |  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    return "\n".join(lines)


# ── Termux (phone-friendly, no box-drawing characters) ─────────────────────
def fmt_termux(results: List[HostResult], args) -> str:
    import shutil
    tw = min(shutil.get_terminal_size().columns, 80) - 2  # usable width
    W = max(tw, 40)
    sep = '─' * W
    has_color = _supports_color()
    _grn = lambda s: f"\033[92m{s}\033[0m" if has_color else s
    _cya = lambda s: f"\033[96m{s}\033[0m" if has_color else s
    _yel = lambda s: f"\033[93m{s}\033[0m" if has_color else s
    _red = lambda s: f"\033[91m{s}\033[0m" if has_color else s
    _bld = lambda s: f"\033[1m{s}\033[0m" if has_color else s

    lines = [BANNER_ART]
    lines.append(f"  {_bld('SCAN REPORT')}")
    lines.append(f"  Started:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Targets:  {len(results)} host(s)")
    lines.append(f"  {sep}")
    lines.append("")

    for idx, res in enumerate(results, 1):
        if not res.up:
            lines.append(f"  {_red('●')} HOST #{idx}: {_sanitize_text(res.host, 30)} — {_red('down')}")
            lines.append("")
            continue

        tags = []
        if res.os_guess: tags.append(f"OS:{res.os_guess}")
        if res.cdn: tags.append(f"CDN:{res.cdn}")
        if res.cloud: tags.append(f"Cloud:{res.cloud}")
        if res.waf: tags.append(f"WAF:{res.waf}")
        tag_str = f"  [{', '.join(tags)}]" if tags else ""

        lines.append(f"  {_grn('●')} {_bld(res.host)}  {res.ip}  {res.latency_ms:.1f}ms{tag_str}")
        if res.reverse_dns:
            lines.append(f"    DNS: {res.reverse_dns}")
        if res.mac:
            lines.append(f"    MAC: {res.mac}  ({res.mac_vendor})")
        lines.append("")

        # Host Overview
        lines.append(f"  {_bld('Host')}")
        lines.append(f"    Hostname:  {res.host}")
        lines.append(f"    IP:        {res.ip}")
        if res.reverse_dns:
            lines.append(f"    DNS:       {res.reverse_dns}")
        if res.mac:
            lines.append(f"    MAC:       {res.mac}  ({res.mac_vendor})")
        lines.append(f"    Latency:   {res.latency_ms:.1f} ms")
        if res.os_guess:
            lines.append(f"    OS:        {res.os_guess} (acc: {res.os_accuracy:.0f}%)")
        for k in ("cdn", "cloud", "waf", "honeypot"):
            v = getattr(res, k, "")
            if v:
                lines.append(f"    {k.title():10} {v}")
        lines.append("")

        # Open Ports
        if res.ports:
            lines.append(f"  {_bld('Open Ports')}")
            lines.append(f"    {'PORT':<7} {'PROTO':<6} {'STATE':<12} {'SERVICE':<{min(W-30,20)}} {'VERSION'}")
            lines.append(f"    {'─'*7} {'─'*6} {'─'*10} {'─'*min(W-30,20)} {'─'*10}")
            for pr in sorted(res.ports, key=lambda x: x.port):
                if args.open and pr.state != "open":
                    continue
                st_colored = _grn(pr.state) if pr.state == "open" else _yel(pr.state)
                sv = _sanitize_text(pr.service or "", min(W-30,20))
                vr = _sanitize_text(pr.version or "", 10)
                lines.append(f"    {pr.port:<7} {pr.protocol.upper():<6} {st_colored:<12} {sv:<{min(W-30,20)}} {vr}")
                if pr.banner and args.banner:
                    lines.append(f"      {_cya('Banner:')} {_sanitize_text(pr.banner, W-20)}")
                if pr.ssl_cert and args.ssl_cert:
                    cn = _sanitize_text(pr.ssl_cert.get("subject",{}).get("commonName","") or "", 30)
                    exp = _sanitize_text(pr.ssl_cert.get("notAfter","") or "", 15)
                    lines.append(f"      {_cya('SSL:')} {cn}  exp:{exp}")
            lines.append("")

        # Web Analysis
        if res.http_tech or res.http_dirs or res.api_endpoints or res.subdomains:
            lines.append(f"  {_bld('Web')}")
            if res.http_tech:
                for name, cat in res.http_tech.items():
                    lines.append(f"    {_sanitize_text(name, 25):<25} {cat}")
            if res.http_dirs:
                for d in res.http_dirs[:10]:
                    sc = _grn(str(d["status"])) if d["status"] == 200 else _yel(str(d["status"]))
                    lines.append(f"    {sc:<6} {_sanitize_text(d['path'], W-20)}")
            if res.api_endpoints:
                for ep in res.api_endpoints[:10]:
                    j = ' (JSON)' if ep['json'] else ''
                    lines.append(f"    {ep['status']:<6} {_sanitize_text(ep['path'], W-20)}{j}")
            if res.subdomains:
                for sd in res.subdomains[:10]:
                    lines.append(f"    {_sanitize_text(sd['subdomain'], 35):<35} {sd['ip']}")
            lines.append("")

        # Traceroute
        if res.traceroute:
            lines.append(f"  {_bld('Traceroute')}")
            for hop in res.traceroute[:10]:
                ip_s = hop['ip'] if hop['ip'] != '*' else _cya('*')
                rtt_s = f"{hop['rtt_ms']:.1f}ms" if hop['rtt_ms'] else _cya('*')
                lines.append(f"    Hop {hop['hop']:<3} {ip_s:<18} {rtt_s}")
            lines.append("")

        # Network Intel
        if res.geo or res.asn or res.shodan or res.whois:
            lines.append(f"  {_bld('Intel')}")
            if res.geo:
                gd = res.geo
                loc = f"{gd.get('city','')}, {gd.get('region','')}, {gd.get('country','')}"
                lines.append(f"    Location:     {_sanitize_text(loc, W-20)}")
                if gd.get('lat') is not None:
                    lines.append(f"    Coordinates:  {gd['lat']}, {gd['lon']}")
            if res.asn:
                lines.append(f"    ASN/ISP:      {res.asn}  ({res.isp})")
            if res.shodan and res.shodan.get("ports"):
                lines.append(f"    Shodan Ports: {', '.join(map(str, res.shodan['ports']))}")
            if res.whois:
                for wl in res.whois.split("\n")[:5]:
                    lines.append(f"    {_sanitize_text(wl, W-6)}")
            lines.append("")

        # Security
        if res.cves or res.brute_creds:
            lines.append(f"  {_bld('Security')}")
            if res.cves:
                for cve in sorted(set(res.cves)):
                    lines.append(f"    {_red(cve)}")
            if res.brute_creds:
                for cred in res.brute_creds:
                    lines.append(f"    {cred['user']}:{cred['password']}")
            lines.append("")

        if idx < len(results):
            lines.append(f"  {'─' * W}")
            lines.append("")

    lines.append(f"  {sep}")
    up_count = sum(1 for r in results if r.up)
    lines.append(f"  {_bld('SCAN COMPLETE')}: {up_count}/{len(results)} hosts up  |  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    return "\n".join(lines)


# ── JSON ─────────────────────────────────────────────────────────────────
def fmt_json(results: List[HostResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2, default=str)


# ── XML ──────────────────────────────────────────────────────────────────
def fmt_xml(results: List[HostResult]) -> str:
    root = ET.Element("promapper", attrib={"version": "3.1"})
    ts = ET.SubElement(root, "scan", attrib={"started": datetime.datetime.now().isoformat()})
    for r in results:
        rh = ET.SubElement(ts, "host", attrib={
            "host": r.host, "ip": r.ip, "up": str(r.up).lower(),
            "os": r.os_guess, "latency_ms": str(r.latency_ms),
        })
        if r.reverse_dns:
            ET.SubElement(rh, "reverse_dns").text = r.reverse_dns
        for pr in r.ports:
            rp = ET.SubElement(rh, "port", attrib={
                "port": str(pr.port), "protocol": pr.protocol,
                "state": pr.state, "service": pr.service, "version": pr.version,
            })
            if pr.banner:
                ET.SubElement(rp, "banner").text = _escape_xml(pr.banner[:200])
            if pr.ssl_cert:
                sc = ET.SubElement(rp, "ssl_cert")
                for k, v in pr.ssl_cert.items():
                    if isinstance(v, dict):
                        sv = ET.SubElement(sc, k)
                        for sk, svv in v.items():
                            ET.SubElement(sv, sk).text = _escape_xml(str(svv))
                    elif isinstance(v, list):
                        sv = ET.SubElement(sc, k)
                        for item in v:
                            ET.SubElement(sv, "item").text = _escape_xml(str(item))
                    else:
                        ET.SubElement(sc, k).text = _escape_xml(str(v))
    return ET.tostring(root, encoding="unicode")


# ── CSV (with formula injection protection) ──────────────────────────────
def fmt_csv(results: List[HostResult]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["host", "ip", "port", "protocol", "state", "service", "version",
                 "banner", "os", "latency_ms", "cdn", "cloud", "waf", "asn"])
    for r in results:
        if not r.ports:
            row = [r.host, r.ip, "", "", "", "", "", "", r.os_guess, r.latency_ms, r.cdn, r.cloud, r.waf, r.asn]
            w.writerow([_escape_cell(str(c)) for c in row])
        else:
            for pr in r.ports:
                row = [r.host, r.ip, pr.port, pr.protocol, pr.state, pr.service,
                       pr.version, pr.banner[:100] if pr.banner else "",
                       r.os_guess, r.latency_ms, r.cdn, r.cloud, r.waf, r.asn]
                w.writerow([_escape_cell(str(c)) for c in row])
    return out.getvalue()


# ── Grepable ──────────────────────────────────────────────────────────────
def fmt_grepable(results: List[HostResult]) -> str:
    glines: List[str] = []
    for r in results:
        if not r.up:
            glines.append(f"Host: {r.host} ({r.ip}) Status: Down")
            continue
        ports_str = ", ".join(sorted(
            f"{pr.port}/{pr.protocol}/{pr.state}/{pr.service}"
            for pr in r.ports if pr.state == "open"
        ))
        glines.append(f"Host: {r.host} ({r.ip}) Status: Up")
        if ports_str:
            glines.append(f"Ports: {ports_str}")
        if r.os_guess:
            glines.append(f"OS: {r.os_guess}")
    return "\n".join(glines)


# ── HTML ─────────────────────────────────────────────────────────────────
def fmt_html(results: List[HostResult]) -> str:
    rows = ""
    for r in results:
        if not r.up:
            rows += f"<tr><td>{_escape_html(r.host)}</td><td>{_escape_html(r.ip)}</td><td colspan='6'>Down</td></tr>\n"
            continue
        geo_str = ""
        if r.geo:
            g = r.geo
            geo_str = f"{_escape_html(g.get('city', ''))}, {_escape_html(g.get('country', ''))}"
        ports_html = "<ul>" + "".join(
            f"<li>{_escape_html(str(pr.port))}/{_escape_html(pr.protocol)} "
            f"<b>{_escape_html(pr.state)}</b> {_escape_html(pr.service)} {_escape_html(pr.version)}"
            f"{' <span class=banner>' + _escape_html(pr.banner[:60]) + '</span>' if pr.banner else ''}</li>"
            for pr in sorted(r.ports, key=lambda x: x.port) if pr.state == "open"
        ) + "</ul>"
        rows += (
            f"<tr>"
            f"<td>{_escape_html(r.host)}<br><small>{_escape_html(r.ip)}</small></td>"
            f"<td>{_escape_html(r.os_guess)}</td>"
            f"<td>{_escape_html(str(r.latency_ms))}ms</td>"
            f"<td>{_escape_html(geo_str)}</td>"
            f"<td>{_escape_html(r.cdn)} {_escape_html(r.cloud)} {_escape_html(r.waf)}</td>"
            f"<td>{ports_html}</td>"
            f"</tr>\n"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>promapper Report - {_escape_html(datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
th {{ background: #161b22; color: #8b949e; }}
tr:nth-child(even) {{ background: #0d1117; }}
tr:hover {{ background: #1c2128; }}
.banner {{ color: #7ee787; font-size: 0.85em; }}
ul {{ margin: 0; padding-left: 20px; }}
small {{ color: #8b949e; }}
</style>
</head>
<body>
<h1>promapper Scan Report</h1>
<p>Generated: {_escape_html(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} | Hosts: {len(results)}</p>
<table>
<tr><th>Host</th><th>OS</th><th>Latency</th><th>Geo</th><th>CDN/Cloud</th><th>Open Ports</th></tr>
{rows}
</table>
</body>
</html>"""
    return html
