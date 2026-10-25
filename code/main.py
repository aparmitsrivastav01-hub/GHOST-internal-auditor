"""Generate the HackerRank Ghost Data Still Exists submission."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

from audit_agent import AuditEngine, read_csv, validate


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    dataset = root / "dataset"
    engine = AuditEngine(dataset)
    requests = read_csv(dataset / "deletion_requests.csv")
    rows = sorted((engine.audit_case(request) for request in requests), key=lambda row: row["case_id"])
    errors = validate(rows, [request["case_id"] for request in requests])
    if errors:
        raise RuntimeError("Output validation failed: " + "; ".join(errors))
    with (root / "output.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)
    diagnostics = root / "code" / "evaluation" / "diagnostics.txt"
    diagnostics.write_text("\n".join(engine.index.diagnostics) or "No evidence parser errors.\n", encoding="utf-8")
    print(f"Wrote {len(rows)} rows to {root / 'output.csv'}; parsed {len(engine.index.observations)} evidence observations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
