"""reconflow.history - Snapshot tracking and scan history management."""

import json
from datetime import datetime
from pathlib import Path


def save_snapshot(out_dir: Path, subs, hosts):
    """Save scan results as a timestamped snapshot under out_dir/runs/<run_id>/."""
    base_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_id = base_id
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    counter = 1
    while (runs_dir / run_id).exists():
        run_id = f"{base_id}_{counter}"
        counter += 1

    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "subdomains": sorted(subs),
        "hosts": hosts or [],
    }
    (run_dir / "snapshot.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return run_id


def list_runs(out_dir: Path):
    """Return a sorted list of run directories containing snapshot.json."""
    runs_dir = out_dir / "runs"
    if not runs_dir.exists() or not runs_dir.is_dir():
        return []
    valid_runs = [p for p in runs_dir.iterdir() if p.is_dir() and (p / "snapshot.json").exists()]
    return sorted(valid_runs, key=lambda p: p.name)


def load_snapshot(run_dir: Path):
    """Load and parse snapshot.json from the specified run directory."""
    snapshot_file = run_dir / "snapshot.json"
    if not snapshot_file.exists():
        raise FileNotFoundError(f"Snapshot file not found: {snapshot_file}")
    return json.loads(snapshot_file.read_text(encoding="utf-8"))
