"""Core functional tests for nmapclone."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nmapclone import ScanConfig, cfg, cfg_set
from nmapclone.datatypes import PortResult, HostResult
from nmapclone.formatters import _escape_cell
from nmapclone.config import _is_valid_target
from nmapclone.lookup import lookup_mac_vendor
from nmapclone.scanner import parse_ports, get_service_name


def test_parse_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert parse_ports("") == []
    assert parse_ports("80,invalid,443") == [80, 443]


def test_is_valid_target():
    assert _is_valid_target("example.com")
    assert _is_valid_target("192.168.1.1")
    assert not _is_valid_target("")
    assert not _is_valid_target("x;rm -rf /")


def test_escape_cell():
    assert _escape_cell("=cmd") == "'=cmd"
    assert _escape_cell("+cmd") == "'+cmd"
    assert _escape_cell("-cmd") == "'-cmd"
    assert _escape_cell("@cmd") == "'@cmd"
    assert _escape_cell("normal") == "normal"
    assert _escape_cell("") == ""


def test_mac_vendor():
    assert lookup_mac_vendor("00:50:56:AB:CD:EF") == "VMware"
    assert lookup_mac_vendor("08:00:27:AB:CD:EF") == "Oracle VirtualBox"
    assert lookup_mac_vendor(None) == ""
    assert lookup_mac_vendor("") == ""


def test_get_service_name():
    assert get_service_name(22) == "ssh"
    assert get_service_name(80) == "http"
    assert get_service_name(443) == "https"
    assert get_service_name(99999) == "unknown"


def test_port_result_cves():
    pr = PortResult(port=80, state="open", cves=["CVE-2021-41773"])
    assert pr.cves == ["CVE-2021-41773"]
    assert pr.port == 80


def test_host_result():
    hr = HostResult(host="test", ip="1.2.3.4", up=True)
    assert hr.host == "test"
    assert hr.ip == "1.2.3.4"
    assert hr.up is True
    hr.ports.append(PortResult(port=22, state="open"))
    assert len(hr.ports) == 1
    assert hr.ports[0].port == 22


def test_scanconfig():
    c = ScanConfig(timeout=5.0, threads=50)
    assert c.timeout == 5.0
    assert c.threads == 50
    cfg_set(c)
    assert cfg().timeout == 5.0
    assert cfg().threads == 50


if __name__ == "__main__":
    test_parse_ports()
    test_is_valid_target()
    test_escape_cell()
    test_mac_vendor()
    test_get_service_name()
    test_port_result_cves()
    test_host_result()
    test_scanconfig()
    print("All tests passed!")
