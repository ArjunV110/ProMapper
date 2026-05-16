"""
Detection modules — OS fingerprinting, WAF, CDN, cloud, honeypot, HTTP tech, CVE checking.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from promapper.config import (
    SSL_PORTS, IS_WINDOWS, IS_TERMUX, HAS_SCAPY,
    cfg, TTL_RE, SSH_BANNER_RE, _get_ssl_ctx,
)
from promapper.scanner import _ping_cmd
from promapper.scanner import resolve_host

logger = logging.getLogger(__name__)

if HAS_SCAPY:
    try:
        from scapy.all import IP, TCP, ICMP, sr1
    except ImportError:
        pass

# ── HTTP Connection Helper ──────────────────────────────────────────────
def _http_conn(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    if port in SSL_PORTS:
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=_get_ssl_ctx())
    return http.client.HTTPConnection(host, port, timeout=timeout)


# ── Pre-compiled Patterns ───────────────────────────────────────────────
_TECH_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(p, re.I), cat, name)
    for p, cat, name in [
        (r'WordPress', 'CMS', 'WordPress'), (r'Drupal', 'CMS', 'Drupal'),
        (r'Joomla', 'CMS', 'Joomla'), (r'Magento', 'CMS', 'Magento'),
        (r'Shopify', 'CMS', 'Shopify'), (r'nginx', 'Web Server', 'Nginx'),
        (r'Apache', 'Web Server', 'Apache HTTPD'), (r'IIS', 'Web Server', 'Microsoft IIS'),
        (r'cloudflare', 'CDN', 'Cloudflare'), (r'CloudFront', 'CDN', 'AWS CloudFront'),
        (r'akamai', 'CDN', 'Akamai'), (r'php', 'Language', 'PHP'),
        (r'asp\.net', 'Language', 'ASP.NET'), (r'express', 'Framework', 'Express.js'),
        (r'django', 'Framework', 'Django'), (r'rails', 'Framework', 'Ruby on Rails'),
        (r'laravel', 'Framework', 'Laravel'), (r'symfony', 'Framework', 'Symfony'),
        (r'jquery', 'Library', 'jQuery'), (r'react', 'Library', 'React'),
        (r'vue', 'Library', 'Vue.js'), (r'angular', 'Library', 'Angular'),
        (r'fastcgi', 'Technology', 'FastCGI'), (r'uwsgi', 'Technology', 'uWSGI'),
        (r'gunicorn', 'Technology', 'Gunicorn'),
    ]
]

_WAF_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(p, re.I), name)
    for p, name in [
        (r'cloudflare', 'Cloudflare'), (r'cf-ray', 'Cloudflare'), (r'__cfduid', 'Cloudflare'),
        (r'ModSecurity', 'ModSecurity'), (r'Sucuri', 'Sucuri CloudProxy'),
        (r'Barracuda', 'Barracuda WAF'), (r'F5 BIG-IP', 'F5 BIG-IP ASM'),
        (r'nginx.+firewall', 'Nginx WAF'), (r'AkamaiGHost', 'Akamai'),
        (r'server: akamai', 'Akamai'), (r'AWS WAF', 'AWS WAF'),
        (r'CloudFront', 'AWS CloudFront'), (r'X-Security', 'Generic WAF'),
        (r'X-Firewall', 'Generic Firewall'), (r'Fortinet', 'Fortinet WAF'),
        (r'Imperva', 'Imperva WAF'), (r'Incapsula', 'Incapsula WAF'),
        (r'StackPath', 'StackPath WAF'), (r'WebKnight', 'WebKnight WAF'),
        (r'Yundun', 'Yundun WAF'), (r'Varnish', 'Varnish (may indicate WAF)'),
    ]
]

_HONEYPOT_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.I) for p in [
        r"ubuntu.*honeypot", r"honeyd", r"dionaea", r"cowrie",
        r"glastopf", r"snare", r"tpot", r"opencanary",
    ]
]


# ── OS Fingerprinting ───────────────────────────────────────────────────
OS_SIGNATURES: List[Dict[str, Any]] = [
    {"name": "Linux 2.4/2.6/3.x/4.x", "ttl_range": (64, 64), "win_range": (5840, 65535), "df": True},
    {"name": "Linux 5.x/6.x", "ttl_range": (64, 64), "win_range": (29000, 65535), "df": True},
    {"name": "Windows 10/11/Server", "ttl_range": (128, 128), "win_range": (65535, 65535), "df": True},
    {"name": "Windows 7/8/Server 2008", "ttl_range": (128, 128), "win_range": (8192, 65535), "df": True},
    {"name": "Windows XP", "ttl_range": (128, 128), "win_range": (65535, 65535), "df": True},
    {"name": "macOS / Darwin", "ttl_range": (64, 64), "win_range": (65535, 65535), "df": True},
    {"name": "FreeBSD", "ttl_range": (64, 64), "win_range": (65535, 65535), "df": True},
    {"name": "OpenBSD", "ttl_range": (64, 64), "win_range": (16384, 16384), "df": True},
    {"name": "Solaris", "ttl_range": (255, 255), "win_range": (8760, 8760), "df": False},
    {"name": "Cisco IOS", "ttl_range": (255, 255), "win_range": (4128, 4128), "df": False},
    {"name": "AIX", "ttl_range": (60, 60), "win_range": (16384, 65535), "df": True},
    {"name": "HP-UX", "ttl_range": (255, 255), "win_range": (32768, 65535), "df": False},
    {"name": "Android", "ttl_range": (64, 64), "win_range": (29200, 65535), "df": True},
]


def guess_os(ip: str, timeout_val: Optional[float] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"name": "Unknown", "accuracy": 0.0, "ttl": 0, "window": 0}
    ttl = 0
    if not HAS_SCAPY:
        try:
            res = subprocess.run(_ping_cmd() + [ip], capture_output=True, timeout=3)
            m = TTL_RE.search(res.stdout)
            if m:
                ttl = int(m.group(1))
                result["ttl"] = ttl
        except Exception:
            pass
    elif HAS_SCAPY:
        try:
            from scapy.all import IP, ICMP, sr1
            ans = sr1(IP(dst=ip) / ICMP(), timeout=timeout_val or cfg().timeout, verbose=0)
            if ans and ans.haslayer(IP):
                ip_layer = ans.getlayer(IP)
                ttl = ip_layer.ttl
                result["ttl"] = ttl
                if ans.haslayer(TCP):
                    tcp_layer = ans.getlayer(TCP)
                    win = tcp_layer.window
                    result["window"] = win
                    df = bool(ip_layer.flags & 0x4000)
                    best_sig, best_score = None, 0
                    for sig in OS_SIGNATURES:
                        score = 0
                        if sig["ttl_range"][0] <= ttl <= sig["ttl_range"][1]:
                            score += 40
                        if sig["win_range"][0] <= win <= sig["win_range"][1]:
                            score += 40
                        if sig["df"] == df:
                            score += 20
                        if score > best_score:
                            best_score = score
                            best_sig = sig
                    if best_sig and best_score >= 40:
                        result["name"] = best_sig["name"]
                        result["accuracy"] = best_score
                else:
                    result["accuracy"] = 40.0
        except Exception as e:
            logger.debug("OS guess error: %s", e)
    if ttl > 0 and result["name"] == "Unknown":
        for sig in OS_SIGNATURES:
            if sig["ttl_range"][0] <= ttl <= sig["ttl_range"][1]:
                result["name"] = sig["name"]
                result["accuracy"] = max(result["accuracy"], 40.0)
                break
    return result


# ── HTTP Technology Detection ───────────────────────────────────────────
def detect_http_tech(host: str, port: int = 80) -> Dict[str, str]:
    techs: Dict[str, str] = {}
    try:
        conn = _http_conn(host, port, cfg().timeout)
        conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0 promapper"})
        resp = conn.getresponse()
        combined = str(resp.headers) + resp.read(50000).decode("utf-8", errors="replace")
        conn.close()
        for pattern, category, name in _TECH_PATTERNS:
            if pattern.search(combined):
                techs[name] = category
        for hdr in ["Server", "X-Powered-By"]:
            val = resp.getheader(hdr, "")
            if val:
                techs[hdr] = val
        sc = resp.getheader("Set-Cookie", "")
        if "PHPSESSID" in sc:
            techs["PHP Sessions"] = "Language"
        if "JSESSIONID" in sc:
            techs["JSP/Servlets"] = "Language"
        if "ASP.NET_SessionId" in sc:
            techs["ASP.NET"] = "Language"
    except Exception as e:
        logger.debug("HTTP tech detect error: %s", e)
    return techs


# ── WAF Detection ───────────────────────────────────────────────────────
def detect_waf(host: str, port: int = 80) -> str:
    try:
        conn = _http_conn(host, port, cfg().timeout)
        conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        combined = str(resp.headers) + resp.read(5000).decode("utf-8", errors="replace")
        conn.close()
        for pattern, name in _WAF_PATTERNS:
            if pattern.search(combined):
                return name
    except Exception:
        pass
    return ""


# ── CDN Detection ───────────────────────────────────────────────────────
CDN_RANGES: Dict[str, List[str]] = {
    "Cloudflare": ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
                   "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
                   "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
                   "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
                   "197.234.240.0/22", "198.41.128.0/17"],
    "Akamai": ["104.64.0.0/10", "23.0.0.0/12", "2.16.0.0/13"],
    "AWS CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "54.182.0.0/16",
                       "204.246.164.0/22", "205.251.192.0/19"],
    "Fastly": ["151.101.0.0/16", "23.235.32.0/20"],
    "StackPath": ["69.164.192.0/18"],
    "Microsoft Azure CDN": ["13.64.0.0/11"],
}


def detect_cdn(ip: str) -> str:
    for name, ranges in CDN_RANGES.items():
        for cidr in ranges:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    return name
            except ValueError:
                pass
    return ""


# ── Cloud Detection ─────────────────────────────────────────────────────
CLOUD_RANGES: Dict[str, List[str]] = {
    "AWS": ["13.32.0.0/15", "13.224.0.0/14", "15.0.0.0/8", "18.0.0.0/8",
            "35.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8"],
    "Google Cloud": ["8.34.0.0/15", "8.35.0.0/16", "23.236.48.0/20",
                     "34.0.0.0/8", "35.184.0.0/14"],
    "Azure": ["13.64.0.0/11", "13.96.0.0/13", "20.0.0.0/8", "40.0.0.0/8"],
    "Oracle Cloud": ["129.146.0.0/17", "132.145.0.0/16", "134.70.0.0/16"],
    "DigitalOcean": ["64.225.0.0/18", "67.205.128.0/18", "104.131.0.0/17",
                     "138.68.0.0/16", "159.203.0.0/16"],
    "Linode": ["45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16"],
    "Vultr": ["45.32.0.0/16", "108.61.0.0/16", "207.148.0.0/16"],
    "Hetzner": ["5.9.0.0/16", "78.46.0.0/16", "88.198.0.0/16"],
    "OVH": ["37.59.0.0/16", "46.105.0.0/16", "51.68.0.0/16", "54.36.0.0/16"],
    "Scaleway": ["51.15.0.0/16", "62.210.0.0/16"],
    "Vercel": ["76.76.21.0/24"],
    "Netlify": ["75.2.0.0/16", "99.83.0.0/16"],
}


def detect_cloud(ip: str) -> str:
    for provider, ranges in CLOUD_RANGES.items():
        for cidr in ranges:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    return provider
            except ValueError:
                pass
    return ""


# ── Honeypot Detection ──────────────────────────────────────────────────
HONEYPOT_PORTS: frozenset = frozenset({22, 23, 80, 443, 3306, 3389, 5900, 8080, 8443})


def detect_honeypot(host: str, port: int, banner: str = "") -> str:
    low = banner.lower()
    for pat in _HONEYPOT_PATTERNS:
        if pat.search(low):
            return f"Possible honeypot (banner matched: {pat.pattern})"
    if port == 22 and "SSH" in banner:
        if not SSH_BANNER_RE.match(banner):
            return "Possible honeypot (atypical SSH banner)"
    return ""


# ── Directory Brute Force ───────────────────────────────────────────────
COMMON_DIRS: List[str] = [
    "admin", "login", "wp-admin", "wp-content", "wp-includes",
    "administrator", "backup", "backups", "config", "css", "js",
    "images", "img", "uploads", "download", "files", "assets",
    "static", "public", "private", "api", "v1", "v2", "graphql",
    "rest", "soap", "xmlrpc", ".git", ".env", ".htaccess",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "phpmyadmin", "pma", "cgi-bin", "server-status", "info.php",
    "test", "debug", "dev", "stage", "beta", "app", "src",
    "dist", "build", "node_modules", "vendor",
]


def dir_brute_force(host: str, port: int, wordlist_path: Optional[str] = None,
                    timeout_val: Optional[float] = None) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    dirs: List[str] = COMMON_DIRS
    if wordlist_path and os.path.isfile(wordlist_path):
        try:
            with open(wordlist_path, errors="replace") as f:
                dirs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.debug("Wordlist error: %s", e)
    t = timeout_val or cfg().timeout
    lock = Lock()

    def check_dir(d: str) -> None:
        try:
            conn = _http_conn(host, port, t)
            path = "/" + d.lstrip("/")
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 promapper"})
            resp = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()
            if status in (200, 201, 204, 301, 302, 307, 403):
                with lock:
                    found.append({"path": path, "status": status})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(len(dirs), 50)) as ex:
        ex.map(check_dir, dirs)
    return found


# ── API Discovery ───────────────────────────────────────────────────────
API_PATTERNS: List[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/rest", "/rest/v1", "/rest/v2", "/soap", "/xmlrpc.php",
    "/api/health", "/api/status", "/api/docs", "/api/swagger",
    "/swagger.json", "/openapi.json", "/api/users", "/api/auth",
    "/api/login", "/api/register", "/api/config", "/api/version",
    "/.well-known/", "/oauth", "/oauth2", "/token", "/auth",
]


def api_discovery(host: str, port: int, timeout_val: Optional[float] = None) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    t = timeout_val or cfg().timeout
    lock = Lock()

    def check_api(path: str) -> None:
        try:
            conn = _http_conn(host, port, t)
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 promapper"})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read(500).decode("utf-8", errors="replace")
            conn.close()
            is_json = False
            try:
                json.loads(body)
                is_json = True
            except (json.JSONDecodeError, ValueError):
                pass
            with lock:
                found.append({"path": path, "status": status, "json": is_json})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(len(API_PATTERNS), 20)) as ex:
        ex.map(check_api, API_PATTERNS)
    return found


# ── Subdomain Enumeration ──────────────────────────────────────────────
COMMON_SUBDOMAINS: List[str] = [
    "www", "mail", "admin", "api", "blog", "dev", "test", "stage",
    "beta", "app", "m", "mobile", "shop", "store", "wiki", "help",
    "support", "docs", "status", "cdn", "static", "assets", "img",
    "images", "video", "media", "files", "download", "ftp", "smtp",
    "imap", "pop3", "webmail", "vpn", "remote", "portal", "login",
    "secure", "ssl", "ns1", "ns2", "ns3", "mx", "server",
]


def subdomain_enum(domain: str, wordlist_path: Optional[str] = None,
                   timeout_val: Optional[float] = None) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    subs: List[str] = COMMON_SUBDOMAINS
    if wordlist_path and os.path.isfile(wordlist_path):
        try:
            with open(wordlist_path, errors="replace") as f:
                subs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.debug("Subdomain wordlist error: %s", e)
    lock = Lock()

    def check_sub(sub: str) -> None:
        try:
            ip = resolve_host(f"{sub}.{domain}")
            if ip:
                with lock:
                    found.append({"subdomain": f"{sub}.{domain}", "ip": ip})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(len(subs), 50)) as ex:
        ex.map(check_sub, subs)
    return found


# ── CVE Checking ────────────────────────────────────────────────────────
CVE_DB: Dict[str, List[Tuple[re.Pattern, Dict[str, List[str]]]]] = {
    "OpenSSH": [
        (re.compile(r"OpenSSH[_-]?(\d+\.\d+)"), {
            "<7.4": ["CVE-2016-10009", "CVE-2016-10010"],
            "<7.5": ["CVE-2017-15906"], "<8.0": ["CVE-2018-15473"],
            "<8.9": ["CVE-2021-41617"],
        }),
    ],
    "Apache httpd": [
        (re.compile(r"Apache/(\d+\.\d+\.\d+)"), {
            "<2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
            "<2.4.50": ["CVE-2021-44790"], "<2.4.54": ["CVE-2022-31813"],
        }),
    ],
    "nginx": [
        (re.compile(r"nginx/(\d+\.\d+\.\d+)"), {
            "<1.20.1": ["CVE-2021-23017"],
            "<1.22.1": ["CVE-2022-41741", "CVE-2022-41742"],
        }),
    ],
    "PHP": [
        (re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)"), {
            ">=8.0<8.0.28": ["CVE-2023-0567"],
            "<7.4.33": ["CVE-2022-31627"],
        }),
    ],
}


def _parse_ver(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0,)


def _ver_lt(a: str, b: str) -> bool:
    try:
        ap = _parse_ver(a)
        bp = _parse_ver(b)
        ml = max(len(ap), len(bp))
        return ap + (0,) * (ml - len(ap)) < bp + (0,) * (ml - len(bp))
    except Exception:
        return False


def check_cves(service_name: str, version_str: str) -> List[str]:
    results: List[str] = []
    for svc, rules in CVE_DB.items():
        if svc.lower() not in service_name.lower():
            continue
        for pattern, version_cves in rules:
            m = pattern.search(version_str)
            if not m:
                continue
            ver = m.group(1)
            for ver_range, cves in version_cves.items():
                try:
                    if ver_range.startswith("<"):
                        if _ver_lt(ver, ver_range[1:]):
                            results.extend(cves)
                    elif ">=" in ver_range and "<" in ver_range:
                        parts = ver_range.split("<")
                        lower, upper = parts[0].replace(">=", ""), parts[1]
                        if not _ver_lt(ver, lower) and _ver_lt(ver, upper):
                            results.extend(cves)
                    elif ver_range.startswith(">="):
                        if not _ver_lt(ver, ver_range[2:]):
                            results.extend(cves)
                except Exception:
                    pass
    return list(set(results))
