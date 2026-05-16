#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# PROMAPPER — Universal A-Z Installer
# Installs everything needed on Linux, macOS, Windows, Termux
# ═══════════════════════════════════════════════════════════════

REPO="https://github.com/ArjunV110/ProMapper.git"
INSTALL_DIR="$HOME/.promapper"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         PROMAPPER — Full A-Z Installation              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Detect OS ──────────────────────────────────────────────────────
OS="unknown"
case "$(uname -s)" in Linux*) OS=linux ;; Darwin*) OS=macos ;; MINGW*|MSYS*) OS=windows ;; esac
if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then OS=termux; fi
echo "  Platform: $OS"
echo ""

# ── Step 1: Clone or update repo ───────────────────────────────────
echo "  [1/5] Cloning PROMAPPER..."
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "         Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --no-rebase 2>/dev/null
else
    rm -rf "$INSTALL_DIR" 2>/dev/null
    git clone --depth 1 "$REPO" "$INSTALL_DIR" 2>/dev/null || {
        echo "  [ERROR] Git clone failed. Install git or check connection."
        exit 1
    }
fi
cd "$INSTALL_DIR"
echo "         Done."
echo ""

# ── Step 2: System packages ────────────────────────────────────────
echo "  [2/5] Installing system packages..."
case $OS in
    termux)
        pkg update -y 2>/dev/null && pkg upgrade -y 2>/dev/null
        pkg install -y python python-cryptography traceroute whois openssh git 2>/dev/null
        ;;
    linux)
        if command -v apt &>/dev/null; then
            sudo apt update -y 2>/dev/null
            sudo apt install -y python3-pip python3-venv traceroute whois git 2>/dev/null
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm python-pip traceroute whois git 2>/dev/null
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3-pip traceroute whois git 2>/dev/null
        else
            echo "         [WARN] Unknown package manager. Install python3, pip, git manually."
        fi
        ;;
    macos)
        if command -v brew &>/dev/null; then
            brew install python traceroute git 2>/dev/null
        else
            echo "         [WARN] Install Homebrew from https://brew.sh first."
        fi
        ;;
    windows)
        echo "         Ensure Python, Git are installed and in PATH."
        ;;
esac
echo "         Done."
echo ""

# ── Step 3: Install Python dependencies ────────────────────────────
echo "  [3/5] Installing Python packages..."
PIP="pip3"
command -v $PIP >/dev/null || PIP="pip"

# Try normal pip first, fallback to --break-system-packages for newer Linux
$PIP install scapy dnspython paramiko 2>/dev/null || \
$PIP install --break-system-packages scapy dnspython paramiko 2>/dev/null || \
echo "         [WARN] Some optional packages failed (scapy needs Npcap on Windows)"

# Install cryptography safely (prefer system package on Termux)
if [ "$OS" = "termux" ]; then
    pkg install -y python-cryptography 2>/dev/null
else
    $PIP install cryptography 2>/dev/null || \
    $PIP install --break-system-packages cryptography 2>/dev/null || true
fi
echo "         Done."
echo ""

# ── Step 4: Install PROMAPPER ───────────────────────────────────────
echo "  [4/5] Installing PROMAPPER..."
$PIP install -e "$INSTALL_DIR" 2>/dev/null || \
$PIP install --break-system-packages -e "$INSTALL_DIR" 2>/dev/null || {
    echo "         Pip install failed. Creating symlink instead..."
    mkdir -p "$HOME/.local/bin" 2>/dev/null
    ln -sf "$INSTALL_DIR/promapper.py" "$HOME/.local/bin/promapper" 2>/dev/null
    # Add to PATH if not already
    case ":$PATH:" in *:"$HOME/.local/bin":*) ;; *) echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.bashrc" ;; esac
}
echo "         Done."
echo ""

# ── Step 5: Verify ──────────────────────────────────────────────────
echo "  [5/5] Verifying installation..."
if command -v promapper &>/dev/null; then
    echo "         $(promapper -V)"
elif [ -f "$HOME/.local/bin/promapper" ]; then
    echo "         $("$HOME/.local/bin/promapper" -V)"
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "         Running from install directory..."
    echo "         $(python3 "$INSTALL_DIR/promapper.py" -V)"
fi
echo ""

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           INSTALLATION COMPLETE!                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Run: promapper scanme.nmap.org -p 22,80 --banner"
echo ""
