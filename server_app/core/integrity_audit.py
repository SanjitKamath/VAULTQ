import json
import os
from pathlib import Path
from typing import Dict, Any


def append_integrity_event(event: Dict[str, Any]) -> str:
    """
    Append-only JSONL integrity event log for forensic/audit trails.
    """
    base_dir = Path(__file__).resolve().parents[1]
    log_dir = base_dir / "storage" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    file_path = log_dir / "integrity_events.jsonl"

    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + os.linesep)

    return str(file_path)
