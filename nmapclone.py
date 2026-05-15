#!/usr/bin/env python3
"""
nmapclone — Production-grade cross-platform network scanner.
Usage: python3 nmapclone.py <target> [options]

Cross-platform: Linux, macOS, Windows, Android Termux.

Examples:
  python3 nmapclone.py scanme.nmap.org -p 22,80 --banner
  python3 nmapclone.py 192.168.1.0/24 -p 1-1024 -O -sV --geo
  python3 nmapclone.py example.com -p 80,443 --http-tech --dir-bust --ssl-cert
  python3 nmapclone.py target.com --brute ssh,ftp --user admin -P wordlist.txt
  python3 nmapclone.py 10.0.0.1 --continuous --diff --html report.html
  python3 nmapclone.py targets.txt -p 22 --ssh-key --os-guess
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nmapclone import __version__
from nmapclone.cli import main

if __name__ == "__main__":
    main()
