#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# PROMAPPER — Universal A-Z Installer
# Auto-detects OS, installs everything needed, works everywhere
# ═══════════════════════════════════════════════════════════════════════

REPO="https://github.com/ArjunV110/ProMapper.git"
INSTALL_DIR="$HOME/.promapper"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         PROMAPPER — Full A-Z Installation              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Detect OS ──────────────────────────────────────────────────────────
OS="unknown"
OS_FULL="$(uname -s)"
ARCH="$(uname -m)"

case "$OS_FULL" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="macos" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
esac

# Termux check (must be before generic Linux)
if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then
    OS="termux"
fi

echo "  Platform    : $OS"
echo "  Architecture: $ARCH"
echo "  Directory   : $INSTALL_DIR"
echo ""

# ── Prerequisites ──────────────────────────────────────────────────────
echo "  ── Checking prerequisites ──"

# Check curl/wget (needed to run this script)
if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    echo "  [REQUIRED] curl or wget — install it first"
    case $OS in
        termux) echo "             pkg install curl" ;;
        linux)  echo "             sudo apt install curl -y  (or pacman/dnf)" ;;
        macos)  echo "             brew install curl" ;;
    esac
    exit 1
fi

# Check/install git
if ! command -v git &>/dev/null; then
    echo "  [INSTALL] git..."
    case $OS in
        termux) pkg install -y git 2>/dev/null ;;
        linux)
            if command -v apt &>/dev/null; then sudo apt install -y git 2>/dev/null
            elif command -v pacman &>/dev/null; then sudo pacman -Sy --noconfirm git 2>/dev/null
            elif command -v dnf &>/dev/null; then sudo dnf install -y git 2>/dev/null; fi ;;
        macos)
            if command -v brew &>/dev/null; then brew install git 2>/dev/null
            else echo "  [WARN] Install git manually from git-scm.com"; fi ;;
    esac
fi
echo "  ✅ git: $(git --version 2>/dev/null | head -c 20 || echo 'not found')"

# Check/install Python
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "  [INSTALL] Python..."
    case $OS in
        termux) pkg install -y python 2>/dev/null ;;
        linux)
            if command -v apt &>/dev/null; then sudo apt install -y python3 python3-pip python3-venv 2>/dev/null
            elif command -v pacman &>/dev/null; then sudo pacman -Sy --noconfirm python python-pip 2>/dev/null
            elif command -v dnf &>/dev/null; then sudo dnf install -y python3 python3-pip 2>/dev/null; fi ;;
        macos)
            if command -v brew &>/dev/null; then brew install python 2>/dev/null; fi ;;
    esac
fi

PYTHON=$(command -v python3 || command -v python)
PYVER=$($PYTHON --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
echo "  ✅ python: $PYTHON ($PYVER)"

# Verify Python 3.9+
if [ "$(echo "$PYVER" | cut -d. -f1)" -lt 3 ] || { [ "$(echo "$PYVER" | cut -d. -f1)" -eq 3 ] && [ "$(echo "$PYVER" | cut -d. -f2)" -lt 9 ]; }; then
    echo "  [ERROR] Python 3.9+ required. Installed: $PYVER"
    exit 1
fi
echo ""

# ── Step 1: Clone/update repo ─────────────────────────────────────────
echo "  ── Step 1/4: Getting PROMAPPER ──"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "  Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --no-rebase 2>/dev/null
    echo "  ✅ Updated"
else
    rm -rf "$INSTALL_DIR" 2>/dev/null
    echo "  Cloning from GitHub..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR" 2>/dev/null || {
        echo "  [ERROR] Clone failed. Check: git, internet, or $REPO"
        exit 1
    }
    echo "  ✅ Cloned"
fi
cd "$INSTALL_DIR"
echo ""

# ── Step 2: Install system packages per OS ────────────────────────────
echo "  ── Step 2/4: Installing system packages ──"
case $OS in
    termux)
        echo "  [Termux] Using pkg..."
        pkg update -y 2>/dev/null
        pkg install -y python-cryptography traceroute whois openssh 2>/dev/null
        echo "  ✅ Termux packages installed"
        ;;
    linux)
        echo "  [Linux] Detecting package manager..."
        if command -v apt &>/dev/null; then
            echo "         Using apt..."
            sudo apt update -y 2>/dev/null
            sudo apt install -y traceroute whois 2>/dev/null
        elif command -v pacman &>/dev/null; then
            echo "         Using pacman..."
            sudo pacman -Sy --noconfirm traceroute whois 2>/dev/null
        elif command -v dnf &>/dev/null; then
            echo "         Using dnf..."
            sudo dnf install -y traceroute whois 2>/dev/null
        else
            echo "         [SKIP] Unknown package manager"
        fi
        echo "  ✅ Linux system packages"
        ;;
    macos)
        echo "  [macOS] Using Homebrew..."
        if command -v brew &>/dev/null; then
            brew install traceroute 2>/dev/null || true
            echo "  ✅ macOS packages installed"
        else
            echo "  [SKIP] Homebrew not found. Install from brew.sh"
        fi
        ;;
    windows)
        echo "  [Windows] Manual steps may be needed:"
        echo "         • Npcap for scapy: https://npcap.com"
        echo "         • Python: https://python.org"
        echo "         • Git: https://git-scm.com"
        ;;
esac
echo ""

# ── Step 3: Install Python packages ───────────────────────────────────
echo "  ── Step 3/4: Installing Python packages ──"
PIP="$PYTHON -m pip"

# Upgrade pip first
$PIP install --upgrade pip 2>/dev/null || true

# Determine pip flags (--break-system-packages for newer Linux)
PIP_FLAGS=""
$PIP install --help 2>/dev/null | grep -q break-system-packages && PIP_FLAGS="--break-system-packages"

# Install optional deps
echo "  Installing optionals: scapy, paramiko, dnspython, cryptography..."
$PIP install $PIP_FLAGS scapy paramiko dnspython 2>/dev/null && echo "  ✅ Optional packages: OK" || echo "  ⚠️  Some optional packages failed"

# Cryptography: prefer system package on Termux, pip elsewhere
case $OS in
    termux) pkg install -y python-cryptography 2>/dev/null && echo "  ✅ Cryptography (system): OK" || echo "  ⚠️  Cryptography: SKIPPED" ;;
    *) $PIP install $PIP_FLAGS cryptography 2>/dev/null && echo "  ✅ Cryptography: OK" || echo "  ⚠️  Cryptography: SKIPPED (SSL fingerprints unavailable)" ;;
esac
echo ""

# ── Step 4: Install PROMAPPER itself ──────────────────────────────────
echo "  ── Step 4/4: Installing PROMAPPER ──"
$PIP install $PIP_FLAGS -e "$INSTALL_DIR" 2>/dev/null && {
    echo "  ✅ PROMAPPER installed via pip"
} || {
    echo "  Pip install failed. Setting up direct execution..."
    mkdir -p "$HOME/.local/bin" 2>/dev/null
    cat > "$HOME/.local/bin/promapper" << 'SYMLINK'
#!/bin/bash
exec python3 "$HOME/.promapper/promapper.py" "$@"
SYMLINK
    chmod +x "$HOME/.local/bin/promapper"
    # Add ~/.local/bin to PATH if not already
    case ":$PATH:" in *:"$HOME/.local/bin":*) ;; *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" ;; esac
    export PATH="$HOME/.local/bin:$PATH"
    echo "  ✅ PROMAPPER installed via symlink"
}
echo ""

# ── Verify ─────────────────────────────────────────────────────────────
echo "  ── Verification ──"
if command -v promapper &>/dev/null; then
    echo "  ✅ $(promapper -V 2>&1)"
    echo "  ✅ Ready to use!"
elif [ -f "$HOME/.local/bin/promapper" ]; then
    echo "  ✅ $("$HOME/.local/bin/promapper" -V 2>&1)"
    export PATH="$HOME/.local/bin:$PATH"
    echo "  ✅ Ready! Restart terminal or run: source ~/.bashrc"
else
    echo "  ✅ $($PYTHON "$INSTALL_DIR/promapper.py" -V 2>&1)"
    echo "  ✅ Run: $PYTHON $INSTALL_DIR/promapper.py scanme.nmap.org"
fi
echo ""

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           INSTALLATION COMPLETE!                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Run: promapper scanme.nmap.org -p 22,80 --banner"
echo ""
