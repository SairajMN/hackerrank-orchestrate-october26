"""Debug: show matched records + decision for specific sample cases."""

from __future__ import annotations

import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))) if False else None
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataset_io import (
    load_user_identities, load_user_audit_log, load_evidence_manifest,
    load_evidence_items, load_deletion_requests, load_deletion_rules,
)
from identity import resolve_user_id, collect_identifiers
from main import find_user_records_by_id, _dedup_records, _is_complete, _rule_action, _end_state
from decision import _is_deletion_request
from evidence import MatchedRecord

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

identities = load_user_identities(os.path.join(DATASET_DIR, "user_identities.csv"))
audit_log = load_user_audit_log(os.path.join(DATASET_DIR, "user_audit_log.csv"))
manifest = load_evidence_manifest(os.path.join(DATASET_DIR, "evidence_files.csv"))
evidence_items = load_evidence_items(manifest)
rules = load_deletion_rules(os.path.join(DATASET_DIR, "deletion_rules.csv"))
rules_by_category = {}
for rule in rules:
    rules_by_category.setdefault(rule.get("data_category", ""), []).append(rule)
reqs = load_deletion_requests(os.path.join(DATASET_DIR, "sample_deletion_requests.csv"))


def show(cid):
    req = [r for r in reqs if r["case_id"] == cid][0]
    uid = resolve_user_id(req["email"], identities, audit_log)
    ids = collect_identifiers(req["email"], uid, identities, audit_log)
    recs = find_user_records_by_id(evidence_items, ids, req["audit_at"])
    recs = _dedup_records(recs)
    print(f"=== {cid}: {req['email']} uid={uid} auth={_is_deletion_request(req['request_text'])} audit_at={req['audit_at']}")
    print("   ids:", {k: sorted(v) for k, v in ids.items()})
    print("   matched records:", len(recs))
    for r in recs:
        action = _rule_action(rules_by_category, r.data_category)
        end = _end_state(action)
        if r.data_category == "DATA_FLOW" and r.state == "ACTIVE":
            end = "DISABLED"
        if r.data_category == "BACKUP_ARCHIVE" and r.state == "ACTIVE":
            end = "BLOCKED"
        viol = "VIOLATION" if r.state != end else "ok"
        print(f"   [{viol}] {r.file_id} {r.system_id} {r.resource_id} {r.data_category} state={r.state} end={end} | {r.detail[:35]} | {r.captured_at}")
    print("   complete?", _is_complete(recs, rules_by_category))


if __name__ == "__main__":
    for cid in sys.argv[1:]:
        show(cid)
