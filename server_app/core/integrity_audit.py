import json
import os
import sys
from pathlib import Path

_IS_WINDOWS = sys.platform.startswith("win")
from typing import Dict, Any


def append_integrity_event(event: Dict[str, Any]) -> str:
    """
    Append-only JSONL integrity event log for forensic/audit trails.
    """
    base_dir = Path(__file__).resolve().parents[1]
    storage_dir = base_dir / "storage"
    log_dir = storage_dir / "logs"
    storage_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    if not _IS_WINDOWS:
        for path in (storage_dir, log_dir):
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
    file_path = log_dir / "integrity_events.jsonl"

    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + os.linesep)

    return str(file_path)
