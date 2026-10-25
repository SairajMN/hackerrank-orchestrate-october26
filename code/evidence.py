"""Evidence matching: reconstruct resource state at audit_at for a subject."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Set
from dataclasses import dataclass

from dataset_io import EvidenceItem, Indexes


@dataclass  # type: ignore[misc]
class MatchedRecord:
    file_id: str
    system_id: str
    resource_id: str
    data_category: str
    state: str
    detail: str
    captured_at: str


def _norm(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _matches_identifier(value: str, ids: Dict[str, Set[str]]) -> bool:
    v = _norm(value).lower()
    if not v:
        return False
    if v in ids["emails"] or v in ids["phones"] or v in ids["email_hashes"]:
        return True
    if v in ids["user_ids"]:
        return True
    if v in ids.get("resource_ids", set()):
        return True
    return False


def _row_matches(row: Dict[str, str], ids: Dict[str, Set[str]]) -> bool:
    for key in (
        "email", "phone", "email_hash", "customer_email", "owner_email",
        "requester_email", "customer_reference", "subject_reference", "lookup_key",
        "resource_id",
    ):
        if _matches_identifier(row.get(key, ""), ids):
            return True
    return False


def _category_for_table(table: str) -> str:
    mapping = {
        "customer_profiles": "USER_PROFILE",
        "customer_search_documents": "SEARCH_INDEX_ENTRY",
        "customer_analytics_profiles": "ANALYTICS_PROFILE",
        "support_records": "SUPPORT_MESSAGE",
        "customer_exports": "USER_EXPORT",
        "connector_subscriptions": "DATA_FLOW",
        "backup_restore_entries": "BACKUP_ARCHIVE",
        "security_audit_records": "SECURITY_AUDIT_LOG",
    }
    return mapping.get(table, "USER_PROFILE")


def _system_for_table(table: str) -> str:
    mapping = {
        "customer_profiles": "account_service",
        "customer_search_documents": "search_service",
        "customer_analytics_profiles": "analytics_platform",
        "support_records": "support_platform",
        "customer_exports": "export_service",
        "connector_subscriptions": "integration_service",
        "backup_restore_entries": "backup_service",
        "security_audit_records": "security_service",
    }
    return mapping.get(table, "account_service")


def _state_sql_row(table: str, row: Dict[str, str]) -> str:
    if table == "customer_profiles":
        status = (row.get("account_status") or "").upper()
        if status in ("DELETED", "ABSENT"):
            return "ABSENT"
        return "PRESENT"
    if table == "customer_search_documents":
        if row.get("email") or row.get("phone") or row.get("email_hash"):
            return "PRESENT"
        return "ABSENT"
    if table == "customer_analytics_profiles":
        if row.get("email") or row.get("phone") or row.get("email_hash"):
            return "PRESENT"
        return "ANONYMIZED"
    if table == "support_records":
        excerpt = (row.get("message_excerpt") or "").strip()
        if excerpt == "[REDACTED]" or not excerpt:
            return "REDACTED"
        return "PRESENT"
    if table == "customer_exports":
        if row.get("owner_email") or row.get("object_key"):
            return "PRESENT"
        return "ABSENT"
    if table == "connector_subscriptions":
        return "ACTIVE" if (row.get("enabled") or "0") == "1" else "INACTIVE"
    if table == "backup_restore_entries":
        return "ACTIVE" if (row.get("restore_allowed") or "0") == "1" else "BLOCKED"
    if table == "security_audit_records":
        return "PRESENT"
    return "PRESENT"


def _merge_json_columns(row: Dict[str, str]) -> Dict[str, str]:
    """If any column value is a JSON object string, merge its keys into the row."""
    merged = dict(row)
    for key, val in row.items():
        if not isinstance(val, str) or not val.startswith("{"):
            continue
        try:
            obj = json.loads(val)
        except Exception:
            continue
        if isinstance(obj, dict):
            for k, v in obj.items():
                merged.setdefault(k, "" if v is None else str(v))
    return merged


_COLLECTION_CATEGORY = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "backup_catalog": "BACKUP_ARCHIVE",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "connector_configurations": "DATA_FLOW",
    "connector_subscriptions": "DATA_FLOW",
    "customer_exports": "USER_EXPORT",
    "support_records": "SUPPORT_MESSAGE",
}

_COLLECTION_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_reports": "analytics_platform",
    "customer_analytics_profiles": "analytics_platform",
    "security_audit_events": "security_service",
    "security_audit_records": "security_service",
    "backup_catalog": "backup_service",
    "backup_restore_entries": "backup_service",
    "connector_configurations": "integration_service",
    "connector_subscriptions": "integration_service",
    "customer_exports": "export_service",
    "support_records": "support_platform",
}


def _resource_category_system(resource_id: str):
    """Derive (category, system) from resource id prefix, the most reliable signal."""
    rid = (resource_id or "").lower()
    if rid.startswith("audit_record"):
        return "SECURITY_AUDIT_LOG", "security_service"
    if rid.startswith("backup_"):
        return "BACKUP_ARCHIVE", "backup_service"
    if rid.startswith("data_flow"):
        return "DATA_FLOW", "integration_service"
    if rid.startswith("search_"):
        return "SEARCH_INDEX_ENTRY", "search_service"
    if rid.startswith("analytics_"):
        return "ANALYTICS_PROFILE", "analytics_platform"
    if rid.startswith("account_") or rid.startswith("tombstone_"):
        return "USER_PROFILE", "account_service"
    if rid.startswith("support_"):
        return "SUPPORT_MESSAGE", "support_platform"
    if rid.startswith("export_"):
        return "USER_EXPORT", "export_service"
    return None, None


def _state_sql_row(merged: Dict[str, str], table: str) -> str:
    collection = (merged.get("collection_name") or merged.get("collection") or "").strip()
    category = _COLLECTION_CATEGORY.get(collection) or _category_for_table(table)

    if category == "ANALYTICS_PROFILE":
        if merged.get("email") or merged.get("phone") or merged.get("email_hash"):
            return "PRESENT"
        return "ANONYMIZED"
    if category == "SEARCH_INDEX_ENTRY":
        doc = merged.get("document")
        email = ""
        if doc:
            try:
                import json as _json
                d = _json.loads(doc) if isinstance(doc, str) else doc
                if isinstance(d, dict):
                    email = d.get("email") or ""
            except Exception:
                email = ""
        if merged.get("email") or email or merged.get("display_name"):
            return "PRESENT"
        return "ABSENT"
    if category == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    if category == "BACKUP_ARCHIVE":
        ra = (merged.get("restore_allowed") or "").lower()
        return "ACTIVE" if ra in ("true", "1", "yes") else "BLOCKED"
    if category == "DATA_FLOW":
        en = (merged.get("enabled") or "").lower()
        return "ACTIVE" if en in ("true", "1", "yes") else "INACTIVE"
    if category == "USER_EXPORT":
        if merged.get("owner_email") or merged.get("object_key"):
            return "PRESENT"
        return "ABSENT"
    if category == "SUPPORT_MESSAGE":
        excerpt = (merged.get("message_excerpt") or merged.get("message_text") or "").strip()
        if excerpt == "[REDACTED]" or not excerpt:
            return "REDACTED"
        return "PRESENT"
    if category == "USER_PROFILE":
        status = (merged.get("account_status") or "").upper()
        if status in ("DELETED", "ABSENT", "NOT_FOUND"):
            return "ABSENT"
        return "PRESENT"
    return "PRESENT"


def _match_sql(item: EvidenceItem, ids: Dict[str, Set[str]]) -> List[MatchedRecord]:
    import json as _json
    out: List[MatchedRecord] = []
    tables = item.parsed or {}
    for table, rows in tables.items():
        if table == "snapshot_scope":
            continue
        for row in rows:
            merged = _merge_json_columns(row)
            resource_id = _norm(merged.get("resource_id"))
            # resource_id prefix is the most reliable category/system signal
            prefix_cat, prefix_sys = _resource_category_system(resource_id)
            collection = (merged.get("collection_name") or merged.get("collection") or "").strip()
            category = prefix_cat or _COLLECTION_CATEGORY.get(collection) or _category_for_table(table)
            system = prefix_sys or merged.get("origin_system") or _COLLECTION_SYSTEM.get(collection) or _system_for_table(table)
            if not _row_matches(merged, ids):
                continue
            state = _state_sql_row(merged, table)
            out.append(MatchedRecord(
                file_id=item.file_id,
                system_id=system,
                resource_id=_norm(merged.get("resource_id")),
                data_category=category,
                state=state,
                detail=_norm(merged.get("email") or merged.get("owner_email")
                             or merged.get("requester_email") or merged.get("message_excerpt")
                             or merged.get("customer_email") or merged.get("subject_selector")),
                captured_at=_norm(merged.get("updated_at")) or item.captured_at,
            ))
    return out

def _walk_json(obj: Any, ids: Dict[str, Set[str]], found: List[Dict[str, Any]], data_store: str = "", captured_at: str = "", file_captured_at: str = "") -> None:
    if isinstance(obj, dict):
        # snapshot bundle: carry data_store and snapshot captured_at down to records
        if "data_store" in obj and "snapshots" not in obj:
            data_store = obj.get("data_store") or data_store
        snap_cap = obj.get("captured_at") if "snapshots" not in obj else None
        if snap_cap:
            captured_at = snap_cap
        rid = _norm(obj.get("resource_id"))
        if rid and (
            _matches_identifier(rid, ids)
            or obj.get("email") or obj.get("subject_reference") or obj.get("customer_reference")
        ):
            if _row_matches(obj, ids):
                rec = dict(obj)
                if data_store and not rec.get("data_store"):
                    rec["data_store"] = data_store
                rec["_captured_at"] = rec.get("observed_at") or captured_at or file_captured_at
                found.append(rec)
        for v in obj.values():
            _walk_json(v, ids, found, data_store, captured_at, file_captured_at)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json(v, ids, found, data_store, captured_at, file_captured_at)


def _state_from_json(rec: Dict[str, Any], doc: Dict[str, Any], system: str, category: str) -> str:
    if category == "ANALYTICS_PROFILE":
        if rec.get("email") or rec.get("phone") or rec.get("email_hash"):
            return "PRESENT"
        return "ANONYMIZED"
    if category == "SUPPORT_MESSAGE":
        text = _norm(rec.get("message_text") or doc.get("message_text") or rec.get("message_excerpt"))
        if text == "[REDACTED]" or not text:
            return "REDACTED"
        return "PRESENT"
    if category == "SEARCH_INDEX_ENTRY":
        if doc.get("email") or doc.get("display_name") or rec.get("email"):
            return "PRESENT"
        return "ABSENT"
    if category == "BACKUP_ARCHIVE":
        ra = _norm(rec.get("restore_allowed")).lower()
        return "BLOCKED" if ra in ("false", "0", "no", "") else "ACTIVE"
    if category == "DATA_FLOW":
        en = _norm(rec.get("enabled")).lower()
        return "INACTIVE" if en in ("false", "0", "no", "") else "ACTIVE"
    if category == "USER_EXPORT":
        if rec.get("owner_email") or rec.get("object_key"):
            return "PRESENT"
        return "ABSENT"
    if category == "USER_PROFILE":
        # Profile lookup with status_code: 404/not_found => ABSENT
        sc = _norm(rec.get("status_code"))
        if sc:
            if sc in ("404", "4040", "not_found") or _norm(rec.get("profile")).lower() in ("null", "none", ""):
                return "ABSENT"
            return "PRESENT"
        resource_id = _norm(rec.get("resource_id")).lower()
        is_tombstone = resource_id.startswith("tombstone_")
        status = _norm(rec.get("account_status")).upper()
        # Tombstone: stable user_id may remain, but direct identifiers must be removed.
        has_direct_ids = bool(
            rec.get("full_name") or rec.get("name") or rec.get("email")
            or rec.get("phone") or rec.get("email_hash")
        )
        if is_tombstone:
            # Tombstone with direct identifiers still exposed = PRESENT (violation, needs REDACT)
            if has_direct_ids:
                return "PRESENT"
            # Tombstone already redacted (only stable reference remains)
            return "REDACTED"
        if status in ("DELETED", "ABSENT"):
            return "ABSENT"
        return "PRESENT"
    return "PRESENT"


def _match_json(item: EvidenceItem, ids: Dict[str, Set[str]]) -> List[MatchedRecord]:
    out: List[MatchedRecord] = []
    parsed = item.parsed

    # connector_configurations shape: top-level records list with subject_reference
    if isinstance(parsed, dict) and "records" in parsed and isinstance(parsed["records"], list):
        for rec in parsed["records"]:
            if isinstance(rec, dict) and _row_matches(rec, ids):
                out.append(MatchedRecord(
                    file_id=item.file_id,
                    system_id=_norm(rec.get("system")),
                    resource_id=_norm(rec.get("resource_id")),
                    data_category=_norm(rec.get("record_type")) or "USER_PROFILE",
                    state="ACTIVE" if _norm(rec.get("result")).upper() == "ACTIVE" else "PRESENT",
                    detail=_norm(rec.get("subject_reference")) or _norm(rec.get("result")),
                    captured_at=item.captured_at,
                ))
        return out

    found: List[Dict[str, Any]] = []
    _walk_json(parsed, ids, found, "", "", item.captured_at)
    for rec in found:
        resource_id = _norm(rec.get("resource_id"))
        doc = rec.get("document") if isinstance(rec.get("document"), dict) else {}
        # resource_id prefix is the most reliable category/system signal
        prefix_cat, prefix_sys = _resource_category_system(resource_id)
        system = _norm(rec.get("system")) or _norm(rec.get("data_store")) or prefix_sys or "account_service"
        category = prefix_cat or _norm(rec.get("record_type"))
        if not category:
            if system == "search_service":
                category = "SEARCH_INDEX_ENTRY"
            elif system == "analytics_platform":
                category = "ANALYTICS_PROFILE"
            elif system == "support_platform":
                category = "SUPPORT_MESSAGE"
            else:
                category = "USER_PROFILE"
        state = _state_from_json(rec, doc, system, category)
        out.append(MatchedRecord(
            file_id=item.file_id,
            system_id=system,
            resource_id=resource_id,
            data_category=category,
            state=state,
            detail=_norm(rec.get("email") or doc.get("email") or rec.get("subject_reference") or rec.get("customer_reference")),
            captured_at=_norm(rec.get("_captured_at")) or item.captured_at,
        ))
    return out


def _log_entry_matches_identifier(entry: Dict[str, str], ids: Dict[str, Set[str]]) -> bool:
    """Check if a log entry directly references the subject via any identifier field."""
    resource_id = _norm(entry.get("resource_id"))
    key_fields = [
        entry.get(k, "") for k in (
            "lookup_key", "match_key", "subject_key", "correlation_key",
            "matched_value", "customer_email", "requester_email",
        )
    ]
    key_vals = [resource_id] + key_fields
    return any(_matches_identifier(v, ids) for v in key_vals)


def _log_entry_to_record(item: EvidenceItem, entry: Dict[str, str], ids: Dict[str, Set[str]]):
    """Convert a single log entry to a MatchedRecord, or None if it carries no state."""
    service = _norm(entry.get("service"))
    resource_id = _norm(entry.get("resource_id"))
    event = _norm(entry.get("event"))
    result = _norm(entry.get("result"))
    rows = _norm(entry.get("rows"))
    http_status = _norm(entry.get("http_status"))
    enabled = _norm(entry.get("enabled"))
    restore_allowed = _norm(entry.get("restore_allowed"))

    # Skip inconclusive in-progress lookup entries (e.g. profile_lookup_started
    # with no rows/http_status). Only terminal entries carry state.
    if service == "account_service" and not rows and not http_status:
        return None
    if service == "search_service" and not result:
        return None

    system = service or "account_service"
    category = "USER_PROFILE"
    state = "PRESENT"
    detail = resource_id

    if service == "account_service":
        category = "USER_PROFILE"
        if rows == "0" or http_status == "404":
            state = "ABSENT"
    elif service == "search_service":
        category = "SEARCH_INDEX_ENTRY"
        if result == "hit":
            state = "PRESENT"
        elif result in ("miss", "not_found") or rows == "0" or http_status == "404":
            state = "ABSENT"
    elif service == "integration_service":
        category = "DATA_FLOW"
        state = "ACTIVE" if enabled == "true" else "INACTIVE"
    elif service == "backup_service":
        category = "BACKUP_ARCHIVE"
        # restore_candidate_evaluated with eligible=true => restore risk (ACTIVE)
        if event == "restore_candidate_evaluated" and _norm(entry.get("eligible")).lower() == "true":
            state = "ACTIVE"
        else:
            state = "ACTIVE" if restore_allowed == "true" else "BLOCKED"
    elif service == "analytics_platform":
        category = "ANALYTICS_PROFILE"
        if rows == "0" or http_status == "404":
            state = "ANONYMIZED"
        else:
            state = "PRESENT"
    elif service == "support_platform":
        category = "SUPPORT_MESSAGE"
        state = "PRESENT"
    elif service == "security_service":
        category = "SECURITY_AUDIT_LOG"
        state = "PRESENT"

    return MatchedRecord(
        file_id=item.file_id,
        system_id=system,
        resource_id=resource_id,
        data_category=category,
        state=state,
        detail=detail,
        captured_at=_norm(entry.get("timestamp")) or item.captured_at,
    )


def _match_log(item: EvidenceItem, ids: Dict[str, Set[str]]) -> List[MatchedRecord]:
    """Match log entries, with trace_id correlation.

    Log entries that reference the subject only via trace_id (the identifier is
    on a sibling line sharing the same trace_id) are included by first finding
    trace_ids that contain a matching identifier, then matching all entries in
    those traces.
    """
    entries = item.parsed or []
    if not entries:
        return []

    # Phase 1: find trace_ids that contain a matching identifier.
    relevant_traces: Set[str] = set()
    direct_results: List[MatchedRecord] = []
    for entry in entries:
        tid = _norm(entry.get("trace_id"))
        if _log_entry_matches_identifier(entry, ids):
            if tid:
                relevant_traces.add(tid)
            rec = _log_entry_to_record(item, entry, ids)
            if rec is not None:
                direct_results.append(rec)

    # Phase 2: match all entries in relevant traces (even if the entry itself
    # has no direct identifier, e.g. connector_heartbeat with enabled=true).
    trace_results: List[MatchedRecord] = []
    if relevant_traces:
        for entry in entries:
            tid = _norm(entry.get("trace_id"))
            if tid in relevant_traces:
                if not _log_entry_matches_identifier(entry, ids):
                    rec = _log_entry_to_record(item, entry, ids)
                    if rec is not None:
                        trace_results.append(rec)

    return direct_results + trace_results




def _match_txt(item: EvidenceItem, ids: Dict[str, Set[str]]) -> List[MatchedRecord]:
    """Parse shift-handover text records:
    timestamp | system | resource_id | category | result | identifier
    """
    out: List[MatchedRecord] = []
    text = item.parsed or ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-") == False and not line[0].isdigit():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6:
            continue
        _ts, system, resource_id, category, result, identifier = parts[:6]
        if not any(_matches_identifier(v, ids) for v in [resource_id, identifier]):
            continue
        result_u = result.upper()
        if result_u in ("NOT_FOUND",):
            state = "ABSENT"
        elif result_u == "ACTIVE":
            state = "ACTIVE"
        elif result_u in ("FOUND", "IDENTIFIABLE"):
            state = "PRESENT"
        elif result_u in ("ANONYMIZED",):
            state = "ANONYMIZED"
        elif result_u in ("BLOCKED", "DISABLED"):
            state = "BLOCKED"
        else:
            state = "PRESENT"
        out.append(MatchedRecord(
            file_id=item.file_id,
            system_id=_norm(system),
            resource_id=_norm(resource_id),
            data_category=_norm(category),
            state=state,
            detail=_norm(identifier),
            captured_at=_norm(_ts) or item.captured_at,
        ))
    return out


def _build_resource_user_map(idx: Indexes) -> Dict[str, Set[str]]:
    """Build a global resource_id -> user_id mapping from all evidence.

    Snapshots and SQL rows link resource_ids to customer_reference/user_id.
    This lets us match log entries that reference a resource_id but not the
    subject's email/phone directly.
    """
    mapping: Dict[str, Set[str]] = {}
    for item in idx.evidence:
        parsed = item.parsed
        if item.kind == "sql":
            for table, rows in (parsed or {}).items():
                if table == "snapshot_scope":
                    continue
                for row in rows:
                    merged = _merge_json_columns(row)
                    rid = _norm(merged.get("resource_id"))
                    if not rid:
                        continue
                    users = set()
                    for key in ("customer_reference", "subject_reference", "user_id"):
                        v = _norm(merged.get(key))
                        if v:
                            users.add(v)
                    if users:
                        mapping.setdefault(rid, set()).update(users)
        elif item.kind == "json":
            # Walk snapshot bundles and exports for resource->user links
            def walk(o):
                if isinstance(o, dict):
                    rid = _norm(o.get("resource_id"))
                    if rid:
                        users = set()
                        for key in ("customer_reference", "subject_reference", "user_id"):
                            v = _norm(o.get(key))
                            if v:
                                users.add(v)
                        if users:
                            mapping.setdefault(rid, set()).update(users)
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
            walk(parsed)
def _match_pdf(item: EvidenceItem, ids: Dict[str, Set[str]]) -> List[MatchedRecord]:
    """Match a PDF text extract against the subject's identifiers.

    If any identifier (email, phone, email_hash, user_id) appears in the PDF
    text, the document contains the subject's PII and is REPORTED as PRESENT.
    Also extracts the support reference as the resource_id if present.
    """
    text = item.parsed or ""
    tl = text.lower()
    extracted_resource_id = ""
    for key in ("emails", "phones", "email_hashes", "user_ids"):
        for v in ids.get(key, set()):
            if v and v in tl:
                # Extract support reference like "support_001" or "CS-4827 / support_001"
                import re
                # Look for support reference patterns in the text
                matches = re.findall(r'support[_]?\s*(\d+)', tl)
                if matches:
                    extracted_resource_id = "support_" + matches[0]
                # Also look for CS- pattern
                cs_matches = re.findall(r'cs[-_]?(\d+)', tl)
                if cs_matches and not extracted_resource_id:
                    extracted_resource_id = "support_" + cs_matches[0]
                if extracted_resource_id:
                    break
        if extracted_resource_id:
            break
    
    for key in (("emails", "phones", "email_hashes", "user_ids")):
        for v in ids.get(key, set()):
            if v and v in tl:
                res_id = extracted_resource_id or ""
                return [MatchedRecord(
                    file_id=item.file_id,
                    system_id="support_platform",
                    resource_id=res_id,
                    data_category="SUPPORT_MESSAGE",
                    state="PRESENT",
                    detail=v,
                    captured_at=item.captured_at,
                )]
    return []

    return mapping


def find_user_records(
    idx: Indexes,
    ids: Dict[str, Set[str]],
    audit_at: str,
    resource_user_map: Dict[str, Set[str]] | None = None,
) -> List[MatchedRecord]:
    """Return every evidence-backed record touching the subject at/before audit_at.

    Records are filtered by their own capture/observed timestamp (not just the
    file-level manifest timestamp) so that post-audit evidence never influences
    a case, and the latest state at/before audit_at wins.

    Cross-evidence correlation: log entries that reference a resource_id linked
    (via snapshots/SQL) to the subject's user_id are also included.
    """
    results: List[MatchedRecord] = []
    # Merge linked resource ids into the match set so all matchers (JSON, SQL,
    # logs, text) can match records that carry only a resource_id.
    match_ids = dict(ids)
    if resource_user_map is not None:
        linked_rids: Set[str] = set()
        for uid in ids.get("user_ids", set()):
            for rid, users in resource_user_map.items():
                if uid in users:
                    linked_rids.add(rid)
        if linked_rids:
            match_ids["resource_ids"] = linked_rids

    for item in idx.evidence:
        if item.kind == "sql":
            results.extend(_match_sql(item, match_ids))
        elif item.kind == "json":
            results.extend(_match_json(item, match_ids))
        elif item.kind == "log":
            results.extend(_match_log(item, match_ids))
        elif item.kind == "text":
            results.extend(_match_txt(item, match_ids))
        elif item.kind == "pdf":
            results.extend(_match_pdf(item, match_ids))
        elif item.kind == "pdf":
            results.extend(_match_pdf(item, match_ids))

    # Keep only records whose own timestamp is at/before audit_at.
    at_or_before = []
    for rec in results:
        cap = rec.captured_at
        if not cap or cap <= audit_at:
            at_or_before.append(rec)
    return at_or_before


