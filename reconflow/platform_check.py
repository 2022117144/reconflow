"""
reconflow.platform_check
------------------------
Detects host OS distribution (Arch/BlackArch, Debian/Ubuntu/Kali/Parrot, Fedora/RHEL)
and provides OS-specific package manager installation hints for missing tools.
"""

import platform
from pathlib import Path

# Tool package mapping for Arch / BlackArch (pacman)
ARCH_PACKAGES = {
    "subfinder": "sudo pacman -S subfinder",
    "httpx": "sudo pacman -S httpx",
    "nuclei": "sudo pacman -S nuclei",
    "ffuf": "sudo pacman -S ffuf",
    "gau": "sudo pacman -S gau",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "gowitness": "go install -v github.com/sensepost/gowitness@latest",
}

# Tool package mapping for Debian / Ubuntu / Kali / Parrot (apt)
DEBIAN_PACKAGES = {
    "subfinder": "sudo apt install subfinder",
    "httpx": "sudo apt install httpx-toolkit",
    "nuclei": "sudo apt install nuclei",
    "ffuf": "sudo apt install ffuf",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "gowitness": "go install -v github.com/sensepost/gowitness@latest",
}

# Tool package mapping for Fedora / RHEL / CentOS (dnf)
FEDORA_PACKAGES = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "gowitness": "go install -v github.com/sensepost/gowitness@latest",
}


def detect_distro() -> str:
    """Return normalized distro name: 'arch', 'debian', 'fedora', or 'unknown'."""
    if platform.system() != "Linux":
        return "unknown"
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            content = os_release.read_text(encoding="utf-8").lower()
            if any(k in content for k in ["arch", "blackarch", "manjaro"]):
                return "arch"
            if any(k in content for k in ["kali", "parrot", "debian", "ubuntu", "pop", "mint"]):
                return "debian"
            if any(k in content for k in ["fedora", "rhel", "centos", "rocky", "almalinux"]):
                return "fedora"
        except Exception:
            pass
    if Path("/etc/arch-release").exists():
        return "arch"
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/fedora-release").exists() or Path("/etc/redhat-release").exists():
        return "fedora"
    return "unknown"


def is_arch_linux() -> bool:
    """Return True if running on Arch Linux or an Arch-derivative like BlackArch."""
    return detect_distro() == "arch"


def is_debian_linux() -> bool:
    """Return True if running on Debian, Ubuntu, Kali Linux, or Parrot OS."""
    return detect_distro() == "debian"


def is_fedora_linux() -> bool:
    """Return True if running on Fedora, RHEL, or CentOS."""
    return detect_distro() == "fedora"


def get_install_hint(tool_name: str) -> str:
    """Return a tailored installation command for the missing tool."""
    if is_arch_linux() and tool_name in ARCH_PACKAGES:
        return f"Install with: {ARCH_PACKAGES[tool_name]}"
    if is_debian_linux() and tool_name in DEBIAN_PACKAGES:
        return f"Install with: {DEBIAN_PACKAGES[tool_name]}"
    if is_fedora_linux() and tool_name in FEDORA_PACKAGES:
        return f"Install with: {FEDORA_PACKAGES[tool_name]}"
    return "Install it to enable this feature."
