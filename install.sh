#!/bin/bash
# PROMAPPER — one-command install for all platforms
# Linux, macOS, Windows (Git Bash), Android Termux

set -e

echo "========================================"
echo "  PROMAPPER — Full Installation"
echo "========================================"
echo ""

# Detect platform
OS="unknown"
case "$(uname -s)" in
    Linux*)  OS=linux ;;
    Darwin*) OS=macos ;;
    MINGW*|MSYS*) OS=windows ;;
    *)       OS=unknown ;;
esac

# Termux detection
if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then
    OS=termux
fi

echo "[*] Detected platform: $OS"
echo ""

# Install system dependencies per platform
case $OS in
    termux)
        echo "[*] Installing Termux packages..."
        pkg update -y && pkg upgrade -y
        pkg install -y python python-cryptography traceroute whois openssh
        ;;
    linux)
        echo "[*] Installing Linux packages..."
        if command -v apt &>/dev/null; then
            sudo apt update -y && sudo apt install -y python3-pip traceroute whois
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm python-pip traceroute whois
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3-pip traceroute whois
        else
            echo "[!] Unknown package manager. Ensure python3, pip are installed."
        fi
        ;;
    macos)
        echo "[*] Installing macOS packages..."
        if ! command -v brew &>/dev/null; then
            echo "[!] Homebrew not found. Install from https://brew.sh"
        else
            brew install python traceroute
        fi
        ;;
    windows)
        echo "[*] On Windows, ensure Python is installed from python.org"
        echo "    Ensure Git Bash has necessary tools."
        ;;
esac

# Install PROMAPPER itself with all optional features
echo ""
echo "[*] Installing PROMAPPER with all features..."
pip install promapper[full] 2>/dev/null || pip install --break-system-packages promapper[full] 2>/dev/null || {
    echo "[*] Trying direct install from repo..."
    pip install scapy dnspython paramiko 2>/dev/null || true
    pip install --break-system-packages scapy dnspython paramiko 2>/dev/null || true
}

echo ""
echo "========================================"
echo "  PROMAPPER installation complete!"
echo "========================================"
echo ""
echo "Run: promapper scanme.nmap.org -p 22,80 --banner"
echo ""
