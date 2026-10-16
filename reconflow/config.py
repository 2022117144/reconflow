"""
reconflow.config
-----------------
Loads user configuration from reconflow.yaml, reconflow.json, or custom paths.
Uses PyYAML if installed, otherwise uses a built-in lightweight fallback parser
so reconflow remains completely dependency-free.
"""

import json
from pathlib import Path

DEFAULT_CONFIG_FILES = [
    Path("reconflow.yaml"),
    Path("reconflow.yml"),
    Path("reconflow.json"),
    Path.home() / ".config" / "reconflow" / "reconflow.yaml",
]


def _simple_yaml_parse(text: str) -> dict:
    """Minimal line-based parser for standard YAML structures without external dependencies."""
    result = {}
    current_section = None

    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if ":" not in stripped:
            continue

        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip().strip("\"'")

        if indent == 0:
            if not val:
                current_section = key
                result[current_section] = {}
            else:
                current_section = None
                result[key] = _cast_value(val)
        elif indent > 0 and current_section:
            result[current_section][key] = _cast_value(val)

    return result


def _cast_value(val: str):
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.isdigit():
        return int(val)
    return val


def load_config(custom_path: str = None) -> dict:
    """Load configuration from custom_path or default candidate locations."""
    target_path = None
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            target_path = p
        else:
            print(f"[!] Specified config file '{custom_path}' not found.")
            return {}
    else:
        for candidate in DEFAULT_CONFIG_FILES:
            if candidate.exists():
                target_path = candidate
                break

    if not target_path:
        return {}

    print(f"[*] Loaded configuration from {target_path}")
    raw_text = target_path.read_text(encoding="utf-8")

    if target_path.suffix.lower() == ".json":
        try:
            return json.loads(raw_text)
        except Exception as e:
            print(f"[!] Failed to parse {target_path}: {e}")
            return {}

    try:
        import yaml
        return yaml.safe_load(raw_text) or {}
    except ImportError:
        return _simple_yaml_parse(raw_text)
