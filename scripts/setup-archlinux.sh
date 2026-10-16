#!/usr/bin/env bash
# scripts/setup-archlinux.sh — Set up reconflow toolchain on Arch Linux / BlackArch
set -euo pipefail

echo "[*] Setting up reconflow toolchain for Arch / BlackArch Linux..."

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Check if BlackArch repository is configured
if ! grep -q "\[blackarch\]" /etc/pacman.conf 2>/dev/null; then
    echo "[*] BlackArch repository not found in /etc/pacman.conf."
    echo "[*] Installing BlackArch strap script..."
    TEMP_DIR=$(mktemp -d)
    curl -s https://blackarch.org/strap.sh -o "$TEMP_DIR/strap.sh"
    chmod +x "$TEMP_DIR/strap.sh"
    $SUDO "$TEMP_DIR/strap.sh"
    rm -rf "$TEMP_DIR"
else
    echo "[+] BlackArch repository already enabled."
fi

# 2. Update pacman package database
echo "[*] Updating pacman database..."
$SUDO pacman -Syu --noconfirm

# 3. Install packaged tools via pacman
echo "[*] Installing pacman-packaged recon tools..."
PACKAGES=(subfinder httpx nuclei ffuf gau assetfinder amass nmap go git)
$SUDO pacman -S --needed --noconfirm "${PACKAGES[@]}"

# 4. Install Go-based tools not packaged or needing latest versions
echo "[*] Installing Go-based tools (naabu, gowitness)..."
if command -v go >/dev/null 2>&1; then
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/sensepost/gowitness@latest

    # Ensure ~/go/bin is in PATH hint
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo "[!] Make sure ~/go/bin is in your PATH: export PATH=\$PATH:\$HOME/go/bin"
    fi
else
    echo "[!] Go compiler not found. Please install Go to build naabu/gowitness."
fi

# 5. Update Nuclei templates
if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates || true
fi

echo "[+] Arch Linux / BlackArch reconflow toolchain setup complete!"
