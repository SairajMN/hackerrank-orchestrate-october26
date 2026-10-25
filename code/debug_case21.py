#!/usr/bin/env python3
"""Debug case_21, case_22, case_26 from sample set"""
import sys, os
sys.path.insert(0, "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/code")

from dataset_io import load_user_identities, load_user_audit_log, load_evidence_manifest, load_evidence_items, load_deletion_rules, load_deletion_requests
from identity import resolve_user_id, collect_identifiers
from main import _is_complete, _is_deletion_request, _dedup_records, find_user_records_by_id, build_steps, steps_to_json
from evidence import _build_resource_user_map

DATASET = "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/dataset"

# Load data
identities = load_user_identities(os.path.join(DATASET, "user_identities.csv"))
audit_log = load_user_audit_log(os.path.join(DATASET, "user_audit_log.csv"))
rules = load_deletion_rules(os.path.join(DATASET, "deletion_rules.csv"))
manifest = load_evidence_manifest(os.path.join(DATASET, "evidence_files.csv"))
evidence_items = load_evidence_items(manifest)
# Load sample deletion requests
sample_requests = load_deletion_requests(os.path.join(DATASET, "sample_deletion_requests.csv"))

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

# Process each failing case from sample set
for case_id in ["case_21", "case_22", "case_26"]:
    print(f"\n=== {case_id} ===")
    request = [r for r in sample_requests if r["case_id"] == case_id][0]
    print(f"email: {request.get('email')}")
    print(f"request_text: {request.get('request_text', '')[:60]}...")
    print(f"audit_at: {request.get('audit_at')}")
    
    # Check if deletion is authorized
    print(f"_is_deletion_request: {_is_deletion_request(request.get('request_text', ''))}")
    
    if not _is_deletion_request(request.get("request_text", "")):
        print("NOT_APPLICABLE (not a deletion request)")
        continue
    
    # Resolve user_id
    user_id = resolve_user_id(request.get("email", ""), identities, audit_log)
    print(f"user_id: {user_id}")
    
    # Collect identifiers
    ids = collect_identifiers(request.get("email", ""), user_id, identities, audit_log)
    print(f"identifiers keys: {list(ids.keys())}")
    for k, v in ids.items():
        print(f"  {k}: {len(v)} values, sample: {list(v)[:3]}")
    
    # Find user records
    audit_at = request.get("audit_at", "")
    records = find_user_records_by_id(evidence_items, ids, audit_at, resource_user_map)
    records = _dedup_records(records)
    print(f"\nTotal records found: {len(records)}")
    for i, r in enumerate(records):
        print(f"  {i}: data_cat={r.data_category} state={r.state} res={r.resource_id} file={r.file_id} sys={r.system_id} cap={r.captured_at}")
    
    # Check completeness
    complete = _is_complete(records, rules_by_category)
    print(f"\n_is_complete: {complete}")
    
    # Build steps
    steps = build_steps(records, rules_by_category, complete)
    print(f"steps count: {len(steps)}")
    for s in steps:
        print(f"  step_no={s.step_no} phase={s.phase} sys={s.system_id} res={s.resource_id} op={s.operation} state={s.state} evid={s.evidence_id}")
    
    # Expected from sample_output
    print(f"\nExpected from sample: COMPLETE (got {complete})")
