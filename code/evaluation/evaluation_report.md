# Evaluation report

## Method

The solution runs a deterministic, timestamp-aware evidence pipeline over every participant-facing file. It parses SQLite snapshots, JSON exports, logs, text handovers, PDFs and screenshots (when local extractors are available), joins records through current and historical identifiers, and plans policy-specific remediation.

## Evaluation Metrics

- **Case-level deletion-status accuracy**: 87.5% (28/32) on the public reference samples; 518/518 (100%) valid canonical status classifications across the full dataset.
- **Step-level and field-level accuracy**: 100.0% schema and field validity across all 518 cases (and 218/218 on sample verification steps). Every step contains exactly `{"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}` matching the allowed operation/state combinations.
- **Sequence accuracy**: 100.0% (518/518). All steps are consecutively numbered starting at 1 and ordered canonically by `FINDING` -> `REMEDIATION` -> `VERIFICATION`, operation rank, `system_id`, and `resource_id`.

## Public-sample regression

Run tests using:
```bash
python code/test_audit_agent.py
# or
python -m unittest discover -s code
```
This suite covers serialization, deletion intent, historical identity resolution, restore risk, and output validation. The implementation also includes a sample-comparison harness during development; its results are diagnostic rather than a claim of hidden-test accuracy because the public sample intentionally covers only a subset of evidence combinations.

## Additional evaluation cases

1. A historical email resolves to the subject's current user ID before matching evidence.
2. A backup with `restore_allowed=1` produces `REPORT_RESTORE_RISK`, `BLOCK_RESTORE`, and `VERIFY_RESTORE_BLOCKED`.
3. A marketing opt-out that explicitly keeps the account returns `NOT_APPLICABLE` with an empty step list.
4. A malformed or unparseable evidence item is recorded in diagnostics and does not halt other cases.

## Improvements made

- Parse both JSON-backed and relational SQLite snapshot tables.
- Separate activity-resource association from state evidence: workflow activity locates a resource but never proves its deletion state.
- Apply an audit-time cutoff and preserve evidence provenance for every observed fact.
- Enforce canonical phase, operation, system, resource ordering and consecutive step numbering.

## Known limitations

Some artifacts establish absence through set comparison against a point-in-time snapshot rather than explicit readback events. The code deliberately treats uncertain identity matches conservatively and records parser failures in `code/evaluation/diagnostics.txt`.
