#!/usr/bin/env python3
"""
promapper — PRO-grade cross-platform network scanner.
Usage: python3 promapper.py <target> [options]

Cross-platform: Linux, macOS, Windows, Android Termux.

Examples:
  python3 promapper.py scanme.nmap.org -p 22,80 --banner
  python3 promapper.py 192.168.1.0/24 -p 1-1024 -O -sV --geo
  python3 promapper.py example.com -p 80,443 --http-tech --dir-bust --ssl-cert
  python3 promapper.py target.com --brute ssh,ftp --user admin -P wordlist.txt
  python3 promapper.py 10.0.0.1 --continuous --diff --html report.html
  python3 promapper.py targets.txt -p 22 --ssh-key --os-guess
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from promapper import __version__
from promapper.cli import main

if __name__ == "__main__":
    main()
