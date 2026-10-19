"""reconflow.cli - Command-line interface and subcommand routing."""

import argparse
import sys
from . import __version__, scan


def build_parser():
    """Construct the main argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="reconflow",
        description="Recon pipeline for bug bounty hunters",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="subcommands",
        description="available operations",
    )

    # scan subcommand
    p_scan = subparsers.add_parser(
        "scan",
        help="Run recon on a domain",
        description="Discover subdomains, filter wildcard DNS, and probe live web services.",
    )
    p_scan.add_argument(
        "domain",
        help="Target domain (must be in scope!)",
    )
    p_scan.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_scan.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads for probing (default: 10)",
    )
    p_scan.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for probing (default: 5)",
    )
    p_scan.add_argument(
        "--keep-wildcard",
        action="store_true",
        help="Warn about wildcard DNS but don't filter wildcard results",
    )
    p_scan.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="Also write structured results to report.json",
    )
    p_scan.add_argument(
        "--screenshots",
        action="store_true",
        help="Capture screenshots of live hosts using gowitness",
    )
    p_scan.add_argument(
        "--scope",
        default=None,
        help="Path to scope file (enforces strict scope boundaries)",
    )

    # diff subcommand
    p_diff = subparsers.add_parser(
        "diff",
        help="Compare the latest two scans for a domain",
        description=(
            "Compare the latest two scan snapshots to detect "
            "newly discovered subdomains and host changes."
        ),
    )
    p_diff.add_argument(
        "domain",
        help="Target domain to compare runs for",
    )
    p_diff.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_diff.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="Output diff comparison as JSON",
    )

    # scope subcommand
    p_scope = subparsers.add_parser(
        "scope",
        help="Check targets against program scope",
        description="Verify whether target hosts, IPs, or CIDRs are IN or OUT of scope.",
    )
    p_scope.add_argument(
        "scope_file",
        help="Path to scope file",
    )
    p_scope.add_argument(
        "targets",
        nargs="+",
        help="One or more target hostnames, URLs, or IPs to check",
    )

    return parser


def main(args=None):
    """Main entrypoint for CLI command dispatch."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.command == "scan":
        scan.run(parsed_args)
    elif parsed_args.command == "diff":
        from . import diff

        diff.run(parsed_args)
    elif parsed_args.command == "scope":
        from . import scope

        scope.run(parsed_args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
