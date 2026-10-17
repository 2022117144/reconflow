#!/usr/bin/env bash
# scripts/setup-debian.sh — Set up reconflow toolchain on Debian, Ubuntu, Kali Linux & Parrot OS
set -euo pipefail

echo "[*] Setting up reconflow toolchain for Debian / Ubuntu / Kali / Parrot..."

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Update package database
echo "[*] Updating apt package lists..."
$SUDO apt-get update -y

# 2. Install baseline system dependencies
echo "[*] Installing baseline packages (git, curl, wget, nmap, golang)..."
$SUDO apt-get install -y --no-install-recommends \
    git curl wget nmap golang-go ca-certificates

# 3. Install available native packages (standard in Kali/Parrot repositories)
echo "[*] Checking for native security packages in repositories..."
KALI_PACKAGES=(subfinder nuclei ffuf httpx-toolkit amass assetfinder)
for pkg in "${KALI_PACKAGES[@]}"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
        echo "[+] Installing native package: $pkg"
        $SUDO apt-get install -y "$pkg" || true
    fi
done

# If httpx-toolkit was installed but 'httpx' command name is missing, provide a symlink
if command -v httpx-toolkit >/dev/null 2>&1 && ! command -v httpx >/dev/null 2>&1; then
    echo "[*] Linking httpx-toolkit to /usr/local/bin/httpx..."
    $SUDO ln -s "$(command -v httpx-toolkit)" /usr/local/bin/httpx || true
fi

# 4. Install Go-based tools not packaged natively or on vanilla Debian/Ubuntu
echo "[*] Checking and installing Go-based tools..."
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

if command -v go >/dev/null 2>&1; then
    if ! command -v subfinder >/dev/null 2>&1; then
        echo "[*] Installing subfinder via go install..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    fi

    if ! command -v httpx >/dev/null 2>&1; then
        echo "[*] Installing httpx via go install..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi

    if ! command -v naabu >/dev/null 2>&1; then
        echo "[*] Installing naabu via go install..."
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    fi

    if ! command -v nuclei >/dev/null 2>&1; then
        echo "[*] Installing nuclei via go install..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    fi

    if ! command -v gau >/dev/null 2>&1; then
        echo "[*] Installing gau via go install..."
        go install -v github.com/lc/gau/v2/cmd/gau@latest
    fi

    if ! command -v ffuf >/dev/null 2>&1; then
        echo "[*] Installing ffuf via go install..."
        go install -v github.com/ffuf/ffuf/v2@latest
    fi

    if ! command -v gowitness >/dev/null 2>&1; then
        echo "[*] Installing gowitness via go install..."
        go install -v github.com/sensepost/gowitness@latest
    fi

    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo "[!] Make sure ~/go/bin is in your PATH: export PATH=\$PATH:\$HOME/go/bin"
    fi
else
    echo "[!] Go compiler not found. Please install Go to compile missing tools."
fi

# 5. Update Nuclei templates if nuclei is present
if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates || true
fi

echo "[+] Debian / Ubuntu / Kali / Parrot reconflow toolchain setup complete!"
