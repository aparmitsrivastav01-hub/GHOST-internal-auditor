"""Deterministic, evidence-grounded deletion audit pipeline."""
from __future__ import annotations

import csv
import json
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_RANK = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}

CATEGORY_BY_COLLECTION = {
    "customer_profiles": "USER_PROFILE", "account_tombstones": "ACCOUNT_TOMBSTONE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY", "search_documents": "SEARCH_INDEX_ENTRY",
    "support_conversations": "SUPPORT_MESSAGE", "support_attachments": "SUPPORT_ATTACHMENT",
    "customer_analytics_reports": "ANALYTICS_PROFILE", "analytics_profiles": "ANALYTICS_PROFILE",
    "product_telemetry": "PRODUCT_TELEMETRY", "customer_export_jobs": "USER_EXPORT",
    "exports": "USER_EXPORT", "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG", "security_audit_events": "SECURITY_AUDIT_LOG",
    "backup_catalog": "BACKUP_ARCHIVE", "connector_configurations": "DATA_FLOW",
    "cache_entries": "CACHE_ENTRY", "secondary_identifiers": "SECONDARY_IDENTIFIER",
}
CATEGORY_BY_PREFIX = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "support": "SUPPORT_MESSAGE",
    "analytics": "ANALYTICS_PROFILE", "telemetry": "PRODUCT_TELEMETRY", "export": "USER_EXPORT",
    "marketing": "MARKETING_PROFILE", "audit_record": "SECURITY_AUDIT_LOG",
    "backup": "BACKUP_ARCHIVE", "data_flow": "DATA_FLOW", "tombstone": "ACCOUNT_TOMBSTONE",
    "cache": "CACHE_ENTRY", "delivery": "EMAIL_DELIVERY_LOG",
}
SYSTEM_BY_CATEGORY = {
    "USER_PROFILE": "account_service", "ACCOUNT_TOMBSTONE": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service", "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform", "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform", "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_platform", "EMAIL_DELIVERY_LOG": "notification_service",
    "SECURITY_AUDIT_LOG": "security_service", "BACKUP_ARCHIVE": "backup_service",
    "DATA_FLOW": "integration_service", "CACHE_ENTRY": "cache_service",
    "SECONDARY_IDENTIFIER": "identity_service",
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def norm(value: Any) -> str:
    return str(value or "").strip().casefold()


def scalar_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from scalar_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from scalar_strings(item)
    elif value is not None:
        yield str(value)


def resource_prefix(resource_id: str) -> str:
    return re.sub(r"_\d+$", "", resource_id)


def category_for(resource_id: str, collection: str = "") -> str:
    if collection in CATEGORY_BY_COLLECTION:
        return CATEGORY_BY_COLLECTION[collection]
    return CATEGORY_BY_PREFIX.get(resource_prefix(resource_id), "USER_PROFILE")


def system_for(category: str, fallback: str = "") -> str:
    return fallback or SYSTEM_BY_CATEGORY.get(category, "account_service")


@dataclass(frozen=True)
class Observation:
    evidence_id: str
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    state: str
    values: tuple[str, ...]


@dataclass
class Subject:
    user_id: str
    identifiers: set[str]


class EvidenceIndex:
    def __init__(self, dataset: Path) -> None:
        self.dataset = dataset
        self.observations: list[Observation] = []
        self.snapshot_catalogs: list[tuple[str, datetime, str, str, set[str]]] = []
        self.diagnostics: list[str] = []
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> list[dict[str, str]]:
        with (self.dataset / "evidence_files.csv").open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def build(self) -> None:
        for item in self.manifest:
            path = self.dataset / item["file_path"]
            captured = parse_time(item["captured_at"])
            try:
                suffix = path.suffix.casefold()
                if suffix == ".json":
                    self._parse_json(path, item["file_id"], captured)
                elif suffix == ".sql":
                    self._parse_sql(path, item["file_id"], captured)
                else:
                    self._parse_text(path, item["file_id"], captured)
            except Exception as exc:  # Evidence must not abort the full audit.
                self.diagnostics.append(f"{item['file_id']}: {type(exc).__name__}: {exc}")

    def _add(self, evidence_id: str, observed_at: datetime, system_id: str,
             resource_id: str, category: str, state: str, value: Any) -> None:
        if not resource_id:
            return
        self.observations.append(Observation(
            evidence_id, observed_at, system_for(category, system_id), resource_id,
            category, state, tuple(norm(item) for item in scalar_strings(value) if norm(item)),
        ))

    def _parse_json(self, path: Path, evidence_id: str, captured: datetime) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        self._walk_json(payload, evidence_id, captured, "", "")

    def _walk_json(self, value: Any, evidence_id: str, captured: datetime,
                   inherited_system: str, inherited_collection: str) -> None:
        if isinstance(value, dict):
            system = str(value.get("data_store") or value.get("system_id") or value.get("service") or inherited_system)
            collection = str(value.get("collection") or value.get("collection_name") or inherited_collection)
            timestamp = parse_time(str(value.get("captured_at") or value.get("updated_at") or value.get("event_time") or captured.isoformat()))
            resource_id = str(value.get("resource_id") or "")
            if resource_id:
                category = category_for(resource_id, collection)
                self._add(evidence_id, timestamp, system, resource_id, category,
                          self._state_from_record(category, value), value)
            for child in value.values():
                self._walk_json(child, evidence_id, captured, system, collection)
        elif isinstance(value, list):
            for child in value:
                self._walk_json(child, evidence_id, captured, inherited_system, inherited_collection)

    def _parse_sql(self, path: Path, evidence_id: str, captured: datetime) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(path.read_text(encoding="utf-8"))
            tables = [row[0] for row in connection.execute("select name from sqlite_master where type='table'")]
            for table in tables:
                columns = {row[1] for row in connection.execute(f'pragma table_info("{table}")')}
                if "resource_id" not in columns:
                    continue
                collection = re.sub(r"_(?:primary|read_replica|reporting_replica|regional_replicas|failover_replica)$", "", table)
                category = category_for("", collection)
                system = system_for(category)
                resource_ids = {row[0] for row in connection.execute(f'SELECT resource_id FROM "{table}"')}
                self.snapshot_catalogs.append((evidence_id, captured, system, category, resource_ids))
                if {"origin_system", "record_json"} <= columns:
                    collection_column = "collection_name" if "collection_name" in columns else "''"
                    time_column = "updated_at" if "updated_at" in columns else "''"
                    query = f'SELECT resource_id, origin_system, {collection_column}, record_json, {time_column} FROM "{table}"'
                    records = ((row[0], row[1], row[2], json.loads(row[3]), row[4]) for row in connection.execute(query))
                else:
                    names = [row[1] for row in connection.execute(f'pragma table_info("{table}")')]
                    query = f'SELECT * FROM "{table}"'
                    records = ((row[0], system, collection, dict(zip(names, row)), row[names.index("updated_at")] if "updated_at" in names else "") for row in connection.execute(query))
                for resource_id, row_system, row_collection, record, when in records:
                    timestamp = parse_time(when) if when else captured
                    category = category_for(resource_id, row_collection or "")
                    self._add(evidence_id, timestamp, system, resource_id, category,
                              self._state_from_record(category, record), record)
        finally:
            connection.close()

    def _read_unstructured(self, path: Path) -> str:
        if path.suffix.casefold() in {".log", ".txt"}:
            return path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.casefold() == ".pdf":
            result = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=False)
            return result.stdout
        if path.suffix.casefold() == ".png":
            result = subprocess.run(["tesseract", str(path), "stdout"], capture_output=True, text=True, check=False)
            return result.stdout
        return ""

    def _parse_text(self, path: Path, evidence_id: str, captured: datetime) -> None:
        text = self._read_unstructured(path)
        context: dict[str, list[str]] = defaultdict(list)
        parsed: list[tuple[datetime, str, str, str, str]] = []
        for line in text.splitlines():
            timestamp_match = re.search(r"(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)", line)
            resource_match = re.search(r"\b((?:account|search|support|analytics|telemetry|export|marketing|audit_record|backup|data_flow|tombstone|cache|delivery)_\d+)\b", line)
            if not resource_match:
                continue
            resource_id = resource_match.group(1)
            timestamp = parse_time(timestamp_match.group(1)) if timestamp_match else captured
            system_match = re.search(r"(?:service=|\|\s*)(account_service|search_service|support_platform|analytics_platform|export_service|integration_service|backup_service|security_service|marketing_platform|identity_service)", line)
            system = system_match.group(1) if system_match else ""
            context[resource_id].append(line)
            parsed.append((timestamp, system, resource_id, line, resource_id))
        for timestamp, system, resource_id, line, key in parsed:
            joined = " ".join(context[key])
            category = category_for(resource_id)
            self._add(evidence_id, timestamp, system, resource_id, category,
                      self._state_from_text(category, line), joined)

    @staticmethod
    def _state_from_record(category: str, record: dict[str, Any]) -> str:
        values = {key.casefold(): value for key, value in record.items()}
        if category == "DATA_FLOW":
            return "ACTIVE" if values.get("enabled") is True or norm(values.get("enabled")) in {"true", "1"} else "DISABLED"
        if category == "BACKUP_ARCHIVE":
            return "ACTIVE" if values.get("restore_allowed") is True or norm(values.get("restore_allowed")) in {"true", "1"} else "BLOCKED"
        direct_fields = ("email", "phone", "email_hash", "full_name", "name", "owner_email", "requester_email")
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return "IDENTIFIABLE" if any(values.get(field) not in (None, "", "[REDACTED]") for field in direct_fields) or values.get("user_id") else "ANONYMIZED"
        if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
            return "IDENTIFIABLE" if any(values.get(field) not in (None, "", "[REDACTED]") for field in direct_fields) else "REDACTED"
        return "PRESENT"

    @staticmethod
    def _state_from_text(category: str, line: str) -> str:
        lower = line.casefold()
        if category == "DATA_FLOW":
            return "ACTIVE" if re.search(r"enabled[=:\s]+(?:true|1)|\bactive\b", lower) else "DISABLED"
        if category == "BACKUP_ARCHIVE":
            return "ACTIVE" if re.search(r"restore_allowed[=:\s]+(?:true|1)|\bactive\b", lower) else "BLOCKED"
        if re.search(r"rows[=:\s]+0|http_status[=:\s]+404|\bnot_found\b|\bnot found\b|\babsent\b", lower):
            return "ABSENT"
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return "ANONYMIZED" if re.search(r"email[=:\s]+null|\banonymized\b", lower) else "IDENTIFIABLE"
        if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
            return "REDACTED" if "[redacted]" in lower or "\bredacted\b" in lower else "IDENTIFIABLE"
        return "PRESENT"


class AuditEngine:
    def __init__(self, dataset: Path) -> None:
        self.dataset = dataset
        self.identity_values, self.email_users = self._load_identities()
        self.rules = self._load_rules()
        self.activities = read_csv(dataset / "system_activity.csv")
        self.index = EvidenceIndex(dataset)
        self.index.build()

    def _load_identities(self) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        values: dict[str, set[str]] = defaultdict(set)
        email_users: dict[str, set[str]] = defaultdict(set)
        with (self.dataset / "user_identities.csv").open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                user_id = row["user_id"]
                values[user_id].update(norm(value) for value in row.values() if norm(value))
                email_users[norm(row["email"])].add(user_id)
        with (self.dataset / "user_audit_log.csv").open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                user_id = row["user_id"]
                for field in ("old_value", "new_value"):
                    if norm(row[field]):
                        values[user_id].add(norm(row[field]))
                if row["field_name"] == "email":
                    for field in ("old_value", "new_value"):
                        if norm(row[field]):
                            email_users[norm(row[field])].add(user_id)
        return values, email_users

    def _load_rules(self) -> dict[str, str]:
        with (self.dataset / "deletion_rules.csv").open(encoding="utf-8", newline="") as handle:
            return {row["data_category"]: row["required_action"] for row in csv.DictReader(handle)}

    @staticmethod
    def requested_deletion(text: str) -> bool:
        lower = norm(text)
        non_deletion = ("unsubscribe", "stop promotional", "stop the promotional", "not asking for deletion",
                        "do not delete", "keep my account", "retain my account")
        deletion_terms = ("delete", "deleting", "deletion", "erase", "erased", "remove my account", "remove my profile", "remove the profile",
                          "remove records", "remove that search", "remove any remaining", "close my account", "close the account",
                          "close this account", "closed", "account closure", "profile is gone", "account was deleted",
                          "suppression", "eliminar", "supresi", "削除")
        return not any(term in lower for term in non_deletion) and any(term in lower for term in deletion_terms)

    def subject_for(self, email: str) -> Subject | None:
        candidates = self.email_users.get(norm(email), set())
        if len(candidates) != 1:
            return None
        user_id = next(iter(candidates))
        return Subject(user_id, self.identity_values[user_id])

    def observations_for(self, subject: Subject, audit_at: datetime, related_ids: set[str]) -> list[Observation]:
        selected: dict[tuple[str, str], Observation] = {}
        for observation in self.index.observations:
            if observation.observed_at > audit_at:
                continue
            values = set(observation.values)
            linked = bool(values.intersection(subject.identifiers)) or any(
                identifier and any(re.search(rf"(?<![a-z0-9_]){re.escape(identifier)}(?![a-z0-9_])", value)
                                   for value in values)
                for identifier in subject.identifiers
            )
            if not linked and observation.resource_id not in related_ids:
                continue
            key = (observation.system_id, observation.resource_id)
            prior = selected.get(key)
            if prior is None or observation.observed_at >= prior.observed_at:
                selected[key] = observation
        return list(selected.values())

    def related_resource_ids(self, request: dict[str, str], audit_at: datetime) -> set[str]:
        reported_at = parse_time(request["reported_at"])
        # Workflow events are useful only to connect a case to a resource; their outcome is never
        # used as a state decision. The source reports are emitted shortly after their operations.
        return {row["resource_id"] for row in self.activities
                if abs((parse_time(row["event_time"]) - reported_at).total_seconds()) <= 900
                and parse_time(row["event_time"]) <= audit_at}

    def absent_snapshot_observations(self, resource_ids: set[str], audit_at: datetime) -> list[Observation]:
        candidates: list[Observation] = []
        for resource_id in resource_ids:
            category = category_for(resource_id)
            matching = [(evidence_id, captured, system) for evidence_id, captured, system, catalog_category, present
                        in self.index.snapshot_catalogs
                        if captured <= audit_at and catalog_category == category and resource_id not in present]
            if matching:
                evidence_id, captured, system = max(matching, key=lambda item: item[1])
                candidates.append(Observation(evidence_id, captured, system, resource_id, category, "ABSENT", ()))
        return candidates

    def audit_case(self, request: dict[str, str]) -> dict[str, str]:
        if not self.requested_deletion(request["request_text"]):
            return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}
        subject = self.subject_for(request["email"])
        if subject is None:
            # Conservatively avoid an unsupported claim of completion.
            return self._serialize(request["case_id"], "INCOMPLETE", [])
        audit_at = parse_time(request["audit_at"])
        related_ids = self.related_resource_ids(request, audit_at)
        observations = self.observations_for(subject, audit_at, related_ids)
        existing_ids = {(item.system_id, item.resource_id) for item in observations}
        observations.extend(item for item in self.absent_snapshot_observations(related_ids, audit_at)
                            if (item.system_id, item.resource_id) not in existing_ids)
        violations = [item for item in observations if self._violation(item)]
        if violations:
            steps = self._incomplete_steps(observations, violations)
            return self._serialize(request["case_id"], "INCOMPLETE", steps)
        steps = [self._verification(item, item.evidence_id) for item in observations if self._is_compliant(item)]
        return self._serialize(request["case_id"], "COMPLETE", steps)

    def _violation(self, item: Observation) -> bool:
        if item.category == "DATA_FLOW":
            return item.state == "ACTIVE"
        if item.category == "BACKUP_ARCHIVE":
            return item.state == "ACTIVE"
        action = self.rules.get(item.category, "DELETE")
        if action == "DELETE":
            return item.state != "ABSENT"
        if action == "REDACT":
            return item.state == "IDENTIFIABLE"
        if action == "ANONYMIZE":
            return item.state == "IDENTIFIABLE"
        return False

    def _is_compliant(self, item: Observation) -> bool:
        if item.category == "DATA_FLOW":
            return item.state == "DISABLED"
        if item.category == "BACKUP_ARCHIVE":
            return item.state == "BLOCKED"
        action = self.rules.get(item.category, "DELETE")
        return {"DELETE": item.state == "ABSENT", "REDACT": item.state == "REDACTED",
                "ANONYMIZE": item.state == "ANONYMIZED", "RETAIN": item.state == "PRESENT"}.get(action, False)

    def _incomplete_steps(self, observations: list[Observation], violations: list[Observation]) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        for item in violations:
            if item.category == "DATA_FLOW":
                steps.append(self._step("FINDING", item, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", item.evidence_id))
            elif item.category == "BACKUP_ARCHIVE":
                steps.append(self._step("FINDING", item, "REPORT_RESTORE_RISK", "ACTIVE", item.evidence_id))
            elif self.rules.get(item.category, "DELETE") == "DELETE":
                steps.append(self._step("FINDING", item, "REPORT_REMAINING_RECORD", "PRESENT", item.evidence_id))
            else:
                steps.append(self._step("FINDING", item, "REPORT_EXPOSED_PII", "PRESENT", item.evidence_id))
        for item in violations:
            operation, state = self._remediation(item)
            steps.append(self._step("REMEDIATION", item, operation, state, ""))
        for item in observations:
            operation, state = self._final_verification(item)
            steps.append(self._step("VERIFICATION", item, operation, state, ""))
        return steps

    def _remediation(self, item: Observation) -> tuple[str, str]:
        if item.category == "DATA_FLOW": return "DISABLE_DATA_FLOW", "DISABLED"
        if item.category == "BACKUP_ARCHIVE": return "BLOCK_RESTORE", "BLOCKED"
        return {"DELETE": ("DELETE_RECORD", "ABSENT"), "REDACT": ("REDACT_RECORD", "REDACTED"),
                "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED")}[self.rules.get(item.category, "DELETE")]

    def _final_verification(self, item: Observation) -> tuple[str, str]:
        if item.category == "DATA_FLOW": return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        if item.category == "BACKUP_ARCHIVE": return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        action = self.rules.get(item.category, "DELETE")
        return {"DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"), "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
                "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"), "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT")}[action]

    def _verification(self, item: Observation, evidence_id: str) -> dict[str, Any]:
        operation, state = self._final_verification(item)
        return self._step("VERIFICATION", item, operation, state, evidence_id)

    @staticmethod
    def _step(phase: str, item: Observation, operation: str, state: str, evidence_id: str) -> dict[str, Any]:
        return {"step_no": 0, "phase": phase, "system_id": item.system_id, "resource_id": item.resource_id,
                "operation": operation, "state": state, "evidence_id": evidence_id}

    @staticmethod
    def _serialize(case_id: str, status: str, steps: list[dict[str, Any]]) -> dict[str, str]:
        steps.sort(key=lambda step: (PHASE_RANK[step["phase"]], OPERATION_RANK[step["operation"]], step["system_id"], step["resource_id"]))
        for step_no, step in enumerate(steps, start=1):
            step["step_no"] = step_no
        return {"case_id": case_id, "deletion_status": status,
                "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False)}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def validate(rows: list[dict[str, str]], expected_cases: list[str]) -> list[str]:
    errors: list[str] = []
    if [row["case_id"] for row in rows] != sorted(expected_cases): errors.append("case IDs are not complete and sorted")
    for row in rows:
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}: errors.append(f"{row['case_id']}: invalid status")
        steps = json.loads(row["steps_json"])
        if row["deletion_status"] == "NOT_APPLICABLE" and steps: errors.append(f"{row['case_id']}: not-applicable steps")
        for number, step in enumerate(steps, 1):
            if set(step) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}: errors.append(f"{row['case_id']}: invalid step fields")
            if step["step_no"] != number: errors.append(f"{row['case_id']}: nonconsecutive steps")
    return errors

