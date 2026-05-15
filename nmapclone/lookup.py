"""
Lookup modules — Geo, WHOIS, Shodan, MAC vendor.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from nmapclone.config import IS_WINDOWS, cfg, SHELL_META

logger = logging.getLogger(__name__)


def _is_valid_lookup_target(host: str) -> bool:
    if not host or not isinstance(host, str) or len(host) > 255:
        return False
    return not bool(SHELL_META.search(host))


def geo_lookup(ip: str, retries: int = 2) -> Dict[str, Any]:
    for attempt in range(retries + 1):
        try:
            url = (
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,countryCode,region,regionName,"
                f"city,zip,lat,lon,timezone,isp,org,as,query"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 nmapclone"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", ""),
                        "countryCode": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "zip": data.get("zip", ""),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "asn": data.get("as", ""),
                    }
                return {}
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
            logger.debug("Geo error (attempt %d): %s", attempt + 1, e)
            if attempt < retries:
                time.sleep(1.0 * (attempt + 1))
        except Exception as e:
            logger.debug("Geo error (attempt %d): %s", attempt + 1, e)
            if attempt < retries:
                time.sleep(1.0 * (attempt + 1))
    return {}


def whois_lookup(host: str) -> str:
    if IS_WINDOWS:
        logger.debug("WHOIS not available on Windows")
        return ""
    if not _is_valid_lookup_target(host):
        logger.debug("Invalid WHOIS target: %s", host)
        return ""
    try:
        res = subprocess.run(["whois", host], capture_output=True, text=True, timeout=15)
        if res.returncode == 0:
            lines = res.stdout.split("\n")
            relevant: List[str] = []
            keywords = ["OrgName", "OrgId", "NetRange", "CIDR", "NetName",
                        "Organization", "RegDate", "Updated", "Country",
                        "Name", "Address", "City", "StateProv", "PostalCode"]
            for line in lines:
                for kw in keywords:
                    if line.strip().startswith(kw):
                        relevant.append(line.strip())
                        break
            return "\n".join(relevant[:30])
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.debug("WHOIS error: %s", e)
    return ""


def shodan_query(ip: str) -> Dict[str, Any]:
    api_key = cfg().shodan_key
    if not api_key:
        return {}
    try:
        req = urllib.request.Request(
            f"https://api.shodan.io/shodan/host/{ip}",
            headers={"User-Agent": "Mozilla/5.0 nmapclone"},
        )
        b64_key = base64.b64encode(f"{api_key}:".encode()).decode()
        req.add_header("Authorization", f"Basic {b64_key}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data if isinstance(data, dict) else {}
    except urllib.error.HTTPError as e:
        logger.debug("Shodan HTTP error: %d %s", e.code, e.reason)
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        logger.debug("Shodan error: %s", e)
    except Exception as e:
        logger.debug("Shodan error: %s", e)
    return {}


MAC_VENDORS: Dict[str, str] = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "00:15:5D": "Microsoft Hyper-V", "00:03:FF": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox", "52:54:00": "QEMU/KVM", "0A:00:27": "Oracle VirtualBox",
    "00:1B:21": "Parallels", "00:25:90": "Parallels",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "AC:1F:6B": "Apple", "F0:18:98": "Apple", "3C:22:FB": "Dell",
    "00:17:A4": "Cisco", "00:1A:6B": "Cisco", "00:0C:42": "Cisco",
}


def lookup_mac_vendor(mac: Optional[str]) -> str:
    if not mac or not isinstance(mac, str):
        return ""
    prefix = mac.upper().replace("-", ":")[:8]
    for vp, vn in MAC_VENDORS.items():
        if prefix.startswith(vp.upper()):
            return vn
    return ""
