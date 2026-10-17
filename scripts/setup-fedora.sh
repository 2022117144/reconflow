#!/usr/bin/env bash
# scripts/setup-fedora.sh — Set up reconflow toolchain on Fedora, RHEL, CentOS & Rocky Linux
set -euo pipefail

echo "[*] Setting up reconflow toolchain for Fedora / RHEL / CentOS / Rocky..."

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Determine package manager (dnf preferred, yum fallback)
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "[-] Error: Neither dnf nor yum package manager found."
    exit 1
fi

# 1. Update package database and install baseline dependencies
echo "[*] Installing baseline packages using $PKG_MGR (git, curl, wget, nmap, golang)..."
$SUDO "$PKG_MGR" install -y git curl wget nmap golang ca-certificates

# 2. Setup Go environment and install reconflow toolchain
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

if command -v go >/dev/null 2>&1; then
    echo "[*] Installing Go-based recon tools..."

    echo "[*] Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    echo "[*] Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

    echo "[*] Installing naabu..."
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

    echo "[*] Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    echo "[*] Installing gau..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest

    echo "[*] Installing ffuf..."
    go install -v github.com/ffuf/ffuf/v2@latest

    echo "[*] Installing gowitness..."
    go install -v github.com/sensepost/gowitness@latest

    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo "[!] Make sure ~/go/bin is in your PATH: export PATH=\$PATH:\$HOME/go/bin"
    fi
else
    echo "[-] Error: Go compiler not found after package installation."
    exit 1
fi

# 3. Update Nuclei templates if nuclei is present
if command -v nuclei >/dev/null 2>&1 || [ -f "$GOPATH/bin/nuclei" ]; then
    echo "[*] Updating nuclei templates..."
    "$GOPATH/bin/nuclei" -update-templates || nuclei -update-templates || true
fi

echo "[+] Fedora / RHEL / CentOS reconflow toolchain setup complete!"
