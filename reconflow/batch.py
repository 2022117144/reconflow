"""
reconflow.batch
-----------------
Batch execution module: enables running reconflow across multiple target domains
defined in an external file (one per line, e.g. -dL targets.txt).
Handles error isolation per target, progress tracking, and batch summary aggregation.
"""

import json
import time
from pathlib import Path


def load_targets(file_path: str | Path) -> list[str]:
    """Load target domains from a file, skipping blanks and comment lines."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Targets file '{file_path}' does not exist.")

    targets = []
    seen = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip protocols or trailing paths if accidentally included
        clean = line.split("://")[-1].split("/")[0].split(":")[0].strip(".").lower()
        if clean and clean not in seen:
            seen.add(clean)
            targets.append(clean)

    return targets


def run_batch(targets: list[str], scan_fn, base_output_dir: Path) -> dict:
    """
    Run scan_fn for each target domain sequentially.
    Ensures that a failure on one target does not halt the entire batch.
    Writes and returns batch_summary.json.
    """
    total = len(targets)
    print(f"[*] Starting batch scan across {total} target domain(s)...")

    results = {}
    successful = 0
    failed = 0
    start_time = time.time()

    for idx, target in enumerate(targets, 1):
        target_start = time.time()
        print(f"\n{'=' * 65}")
        print(f"[*] [{idx}/{total}] Target: {target}")
        print(f"{'=' * 65}")

        try:
            summary = scan_fn(target)
            elapsed = round(time.time() - target_start, 2)
            results[target] = {
                "status": "success",
                "elapsed_seconds": elapsed,
                "summary": summary if isinstance(summary, dict) else {},
            }
            successful += 1
            print(f"[+] [{idx}/{total}] Finished {target} in {elapsed}s")
        except Exception as e:
            elapsed = round(time.time() - target_start, 2)
            results[target] = {
                "status": "error",
                "elapsed_seconds": elapsed,
                "error": str(e),
            }
            failed += 1
            print(f"[!] [{idx}/{total}] Failed {target} after {elapsed}s: {e}")

    total_elapsed = round(time.time() - start_time, 2)
    batch_summary = {
        "total_targets": total,
        "successful": successful,
        "failed": failed,
        "total_elapsed_seconds": total_elapsed,
        "targets": results,
    }

    base_output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = base_output_dir / "batch_summary.json"
    summary_file.write_text(json.dumps(batch_summary, indent=2), encoding="utf-8")

    print(f"\n{'=' * 65}")
    print(f"[+] Batch execution complete: {successful} succeeded, {failed} failed "
          f"({total_elapsed}s total)")
    print(f"[+] Batch summary saved to {summary_file}")
    print(f"{'=' * 65}\n")

    return batch_summary
