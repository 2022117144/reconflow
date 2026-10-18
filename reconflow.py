#!/usr/bin/env python3
"""reconflow legacy script entrypoint (delegates to reconflow.scan)."""

from reconflow import scan
from reconflow.scan import (
    RESOLVE_THREADS,
    capture_screenshots,
    check_tools,
    find_subdomains,
    main,
    probe_hosts,
    resolve,
    run_cmd,
    write_report,
)

# Backwards compatibility re-exports
run = run_cmd

__all__ = [
    "RESOLVE_THREADS",
    "capture_screenshots",
    "check_tools",
    "detect_wildcard",
    "filter_wildcard",
    "find_subdomains",
    "main",
    "probe_hosts",
    "resolve",
    "run",
    "run_cmd",
    "write_report",
]


def detect_wildcard(domain, min_samples=5, max_samples=20, stable_rounds=3):
    """Detect wildcard DNS delegating to scan module with dynamic resolve injection."""
    return scan.detect_wildcard(
        domain,
        min_samples=min_samples,
        max_samples=max_samples,
        stable_rounds=stable_rounds,
        resolve_fn=resolve,
    )


def filter_wildcard(subs, wildcard_ips):
    """Filter wildcard subdomains delegating to scan module with dynamic resolve injection."""
    return scan.filter_wildcard(subs, wildcard_ips, resolve_fn=resolve)


if __name__ == "__main__":
    main()
