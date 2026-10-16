"""
reconflow.platform_check
------------------------
Detects host OS distribution (specifically Arch Linux / BlackArch) and
provides OS-specific package manager installation hints for missing tools.
"""

import platform
from pathlib import Path

# Tool package mapping for Arch/BlackArch
ARCH_PACKAGES = {
    "subfinder": "sudo pacman -S subfinder",
    "httpx": "sudo pacman -S httpx",
    "nuclei": "sudo pacman -S nuclei",
    "ffuf": "sudo pacman -S ffuf",
    "gau": "sudo pacman -S gau",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "gowitness": "go install -v github.com/sensepost/gowitness@latest",
}


def is_arch_linux() -> bool:
    """Return True if running on Arch Linux or an Arch-derivative like BlackArch."""
    if platform.system() != "Linux":
        return False
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            content = os_release.read_text(encoding="utf-8").lower()
            return "arch" in content or "blackarch" in content
        except Exception:
            pass
    return Path("/etc/arch-release").exists()


def get_install_hint(tool_name: str) -> str:
    """Return a tailored installation command for the missing tool."""
    if is_arch_linux() and tool_name in ARCH_PACKAGES:
        return f"Install with: {ARCH_PACKAGES[tool_name]}"
    return "Install it to enable this feature."
