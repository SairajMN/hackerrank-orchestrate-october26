#!/usr/bin/env python3
"""Debug the 3 failing sample cases"""
import sys
sys.path.insert(0, "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/code")

from dataset_io import load_user_identities, load_user_audit_log, load_evidence_manifest, load_evidence_items, load_deletion_rules
from identity import collect_identifiers, resolve_user_id
from main import _is_deletion_request, _is_complete, build_steps
from evidence import find_user_records, _build_resource_user_map
import csv

# Load data
identities = load_user_identities("dataset/user_identities.csv")
audit_log = load_user_audit_log("dataset/user_audit_log.csv")
rules = load_deletion_rules("dataset/deletion_rules.csv")
manifest = load_evidence_manifest("dataset/evidence_files.csv")
evidence_items = load_evidence_items("dataset/evidence_files.csv")
requests = load_deletion_requests("dataset/sample_deletion_requests.csv")

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

# Process each failing case from the SAMPLE set
for case_id in ["case_21", "case_22", "case_26"]:
    print(f"\n=== {case_id} ===")
    request = [r for r in requests if r["case_id"] == case_id][0]
    print(f"email: {request.get('email')}")
    print(f"request_text: {request.get('request_text', '')[:60]}...")
    print(f"audit_at: {request.get('audit_at')}")
    
    # Check if deletion is authorized
    del_authorized = _is_deletion_request(request.get("request_text", ""))
    print(f"_is_deletion_request: {del_authorized}")
    
    if not del_authorized:
        print("NOT_APPLICABLE - would be NOT_APPLICABLE")
        continue
    
    # Resolve user_id
    user_id = resolve_user_id(request.get("email", ""), identities, audit_log)
    print(f"user_id: {user_id}")
    
    # Collect identifiers
    ids = collect_identifiers(request.get("email", ""), user_id, identities, audit_log)
    print(f"identifiers keys: {list(ids.keys())}")
    for k, v in ids.items():
        print(f"  {k}: {list(v)[:5]}")
    
    # Find user records
    audit_at = request.get("audit_at", "")
    records = find_user_records(all_idx, ids, audit_at, resource_user_map)
    print(f"records found: {len(records)}")
    for i, r in enumerate(records[:30]):
        print(f"  {i}: data_cat={r.data_cat} state={r.state} res={r.resource_id} file={r.file_id} sys={r.system_id} cap={r.captured_at}")
    
    # Check completeness
    complete = _is_complete(records, rules_by_category)
    print(f"_is_complete: {complete}")
    
    # Build steps
    steps = build_steps(records, rules_by_category, complete)
    print(f"steps count: {len(steps)}")
    for s in steps:
        print(f"  step_no={s.step_no} phase={s.phase} sys={s.system_id} res={s.resource_id} op={s.operation} state={s.state} evid={s.evidence_id}")