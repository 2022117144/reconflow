#!/usr/bin/env bash
# scripts/setup.sh — Universal Linux installer for reconflow
# Auto-detects Linux distribution and launches the appropriate setup script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================="
echo "   reconflow — Universal Linux Toolchain Installer       "
echo "========================================================="

# Detect distribution via /etc/os-release
DISTRO="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
    COMBINED="$(echo "$OS_ID $OS_LIKE" | tr '[:upper:]' '[:lower:]')"

    if echo "$COMBINED" | grep -qE "arch|blackarch|manjaro|endeavouros"; then
        DISTRO="arch"
    elif echo "$COMBINED" | grep -qE "kali|parrot|debian|ubuntu|pop|mint"; then
        DISTRO="debian"
    elif echo "$COMBINED" | grep -qE "fedora|rhel|centos|rocky|almalinux"; then
        DISTRO="fedora"
    fi
fi

# Fallback detection using release files
if [ "$DISTRO" = "unknown" ]; then
    if [ -f /etc/arch-release ]; then
        DISTRO="arch"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
        DISTRO="fedora"
    fi
fi

case "$DISTRO" in
    arch)
        echo "[+] Detected Arch Linux / BlackArch / derivative."
        chmod +x "$SCRIPT_DIR/setup-archlinux.sh"
        exec "$SCRIPT_DIR/setup-archlinux.sh" "$@"
        ;;
    debian)
        echo "[+] Detected Debian / Ubuntu / Kali / Parrot."
        chmod +x "$SCRIPT_DIR/setup-debian.sh"
        exec "$SCRIPT_DIR/setup-debian.sh" "$@"
        ;;
    fedora)
        echo "[+] Detected Fedora / RHEL / CentOS / Rocky."
        chmod +x "$SCRIPT_DIR/setup-fedora.sh"
        exec "$SCRIPT_DIR/setup-fedora.sh" "$@"
        ;;
    *)
        echo "[!] Could not automatically detect distribution family."
        echo "    Available setup scripts in scripts/:"
        echo "    - scripts/setup-debian.sh    (Debian, Ubuntu, Kali Linux, Parrot OS)"
        echo "    - scripts/setup-archlinux.sh (Arch Linux, BlackArch, Manjaro)"
        echo "    - scripts/setup-fedora.sh    (Fedora, RHEL, CentOS, Rocky Linux)"
        exit 1
        ;;
esac
