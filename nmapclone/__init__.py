"""
nmapclone — Production-grade cross-platform network scanner.
Cross-platform: Linux, macOS, Windows, Android Termux.
"""

__version__ = "3.1.0"
__author__ = "nmapclone Team"
__license__ = "MIT"

from nmapclone.config import ScanConfig, cfg, cfg_set
from nmapclone.datatypes import PortResult, HostResult
from nmapclone.formatters import (
    fmt_terminal, fmt_json, fmt_xml, fmt_csv, fmt_grepable, fmt_html,
)
