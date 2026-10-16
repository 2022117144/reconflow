"""
reconflow.state
----------------
Manages run state and progress tracking so scans can be resumed
if interrupted, and results are safely streamed to disk.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


class StateManager:
    def __init__(self, output_dir: Path, domain: str, resume: bool = False):
        self.output_dir = output_dir
        self.domain = domain
        self.resume = resume
        self.state_file = output_dir / "state.json"
        self.state = self._load_or_init()

    def _load_or_init(self) -> dict:
        if self.resume and self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                print(f"[*] Resuming previous scan for {self.domain} from {self.state_file}")
                return data
            except Exception as e:
                print(f"[!] Could not load state file: {e}. Starting fresh.")
        return {
            "domain": self.domain,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "stages_completed": [],
        }

    def is_completed(self, stage: str) -> bool:
        return self.resume and stage in self.state.get("stages_completed", [])

    def mark_completed(self, stage: str, metadata: dict = None):
        if stage not in self.state["stages_completed"]:
            self.state["stages_completed"].append(stage)
        self.state["updated_at"] = datetime.now(timezone.utc).isoformat()
        if metadata:
            self.state.setdefault("metadata", {})[stage] = metadata
        self._flush()

    def _flush(self):
        try:
            self.state_file.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[!] Warning: failed to flush state: {e}")
