import json
import time
from pathlib import Path

LOG = Path(__file__).resolve().parents[1] / "logs" / "llm_security.log"


def event(kind: str, **fields):
    """One JSON object per line. Wazuh can ingest this file (see wazuh/)."""
    LOG.parent.mkdir(exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind, **fields}
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
