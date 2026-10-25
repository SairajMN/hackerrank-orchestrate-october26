#!/usr/bin/env python3
"""Debug the three failing sample cases"""
import sys
sys.path.insert(0, "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/code")

from decision import _rule_for_category, _end_state_for_record, _normalize_state
from identity import resolve_user_id, collect_identifiers
from dataset_io import load_user_identities, load_user_audit_log, load_evidence_manifest, load_evidence_items, load_deletion_rules, load_deletion_requests
from evidence import _build_resource_user_map
from main import _is_complete, find_user_records_by_id

# Load data
identities = load_user_identities("dataset/user_identities.csv")
audit_log = load_user_audit_log("dataset/user_audit_log.csv")
rules = load_deletion_rules("dataset/deletion_rules.csv")
manifest = load_evidence_manifest("dataset/evidence_files.csv")
evidence_items = load_evidence_items(manifest)
requests = load_deletion_requests("dataset/deletion_requests.csv")

# Build rules_by_category
rules_by_category = {}
for rule in rules:
    rules_by_category.setdefault(rule.get("data_category", ""), []).append(rule)

# Build resource_user_map
class _Idx:
    pass
all_idx = _Idx()
all_idx.evidence = evidence_items
resource_user_map = _build_resource_user_map(all_idx)

# Process each failing case
failing_cases = ["case_21", "case_22", "case_26"]
for case_id in failing_cases:
    print(f"=== {case_id} ===")
    # Find the request
    request = None
    for r in requests:
        if r["case_id"] == case_id:
            request = r
            break
    if request is None:
        print(f"  Request not found for {case_id}")
        print()
        continue
    
    email = request["email"]
    audit_at = request["audit_at"]
    
    user_id = resolve_user_id(email, identities, audit_log)
    ids = collect_identifiers(email, user_id, identities, audit_log)
    records = find_user_records_by_id(evidence_items, ids, audit_at, resource_user_map)
    records = sorted(records, key=lambda r: r.captured_at)
    
    print(f"user_id: {user_id}")
    print(f"identifiers: {list(ids.keys())}")
    print(f"records found: {len(records)}")
    for i, r in enumerate(records[:30]):
        cat = r.data_category
        state = r.state
        action = _rule_for_category(rules_by_category, cat)
        end_state = _end_state_for_record(cat, state, r.resource_id, action)
        norm_state = _normalize_state(cat, state)
        print(f"  {i}: cat={cat} state={state} resource_id={r.resource_id} action={action} end_state={end_state} norm_state={norm_state} file={r.file_id}")
    
    complete = _is_complete(records, rules_by_category)
    print(f"_is_complete result: {complete}")
    print()