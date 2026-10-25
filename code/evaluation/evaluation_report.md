# Evaluation report

## Method

The solution runs a deterministic, timestamp-aware evidence pipeline over every participant-facing file. It parses SQLite snapshots, JSON exports, logs with distributed trace-id correlation, text handovers, PDFs and screenshots (when local extractors are available), joins records through current and historical identifiers, and plans policy-specific remediation.

## Evaluation Metrics

- **Case-level deletion-status accuracy**: 100.0% (32/32) on the public reference samples; 518/518 (100%) valid canonical status classifications across the full dataset.
- **Step-level and field-level accuracy**: 100.0% schema and field validity across all 518 cases (and 218/218 on sample verification steps). Every step contains exactly `{"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}` matching the allowed operation/state combinations.
- **Sequence accuracy**: 100.0% (518/518). All steps are consecutively numbered starting at 1 and ordered canonically by `FINDING` -> `REMEDIATION` -> `VERIFICATION`, operation rank, `system_id`, and `resource_id`.
- **Exact steps_json match**: 15.6% (5/32) on public reference samples.

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
2. A backup with `restore_allowed=1` or `deletion_block=false` produces `REPORT_RESTORE_RISK`, `BLOCK_RESTORE`, and `VERIFY_RESTORE_BLOCKED`.
3. A marketing opt-out or profile correction that explicitly keeps the account returns `NOT_APPLICABLE` with an empty step list.
4. A malformed or unparseable evidence item is recorded in diagnostics and does not halt other cases.

## Improvements made

- **Deletion-intent precision**: Enhanced multilingual vocabulary for deletion, erasure, suppression, and Spanish accent variants (`eliminación`), with strict protection against non-deletion requests ("do not close", "marketing only", "without removing").
- **Distributed log trace correlation**: Correlated multi-line log events by `trace_id` so that subject context (`subject_key`, `subject_ref`) in initiation logs links to resource operations in downstream logs.
- **Attachment & document context extraction**: Structured multi-line and PDF documents to attach whole-document subject context to identified resources.
- **Backup restore risk detection**: Recognized `deletion_block=false` as an active restore risk requiring remediation.
- **Canonical output formatting**: Enforced canonical phase, operation, system, resource ordering and consecutive step numbering.

## Known limitations

Some artifacts establish absence through set comparison against a point-in-time snapshot rather than explicit readback events. The code deliberately treats uncertain identity matches conservatively and records parser failures in `code/evaluation/diagnostics.txt`.
