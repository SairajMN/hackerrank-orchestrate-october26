#!/usr/bin/env python3
"""Debug the 3 failing sample cases"""
import sys
sys.path.insert(0, "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/code")

from main import audit_case, _is_deletion_request
from dataset_io import (
    load_deletion_requests, load_deletion_rules, load_evidence_items, load_evidence_manifest,
    load_user_audit_log, load_user_identities, build_indexes
)
from evidence import _build_resource_user_map

# Load data
identities = load_user_identities("dataset/user_identities.csv")
audit_log = load_user_audit_log("dataset/user_audit_log.csv")
rules = load_deletion_rules("dataset/deletion_rules.csv")
manifest = load_evidence_manifest("dataset/evidence_files.csv")
evidence_items = load_evidence_items(manifest)
requests = load_deletion_requests("dataset/sample_deletion_requests.csv")

# Build rules_by_category
rules_by_category = {}
for rule in rules:
    rules_by_category.setdefault(rule.get("data_category", ""), []).append(rule)

# Build resource_user_map via build_indexes + _build_resource_user_map
idx = build_indexes(identities, audit_log, rules, evidence_items)
resource_user_map = _build_resource_user_map(idx)

# Process each failing case
for case_id in ["case_21", "case_22", "case_26"]:
    print(f"\n=== {case_id} ===")
    request = [r for r in requests if r["case_id"] == case_id][0]
    print(f"email: {request.get('email')}")
    print(f"request_text: {request.get('request_text', '')[:80]}...")
    print(f"audit_at: {request.get('audit_at')}")
    
    # Check deletion authorization
    del_auth = _is_deletion_request(request.get("request_text", ""))
    print(f"_is_deletion_request: {del_auth}")
    
    # Run audit_case
    cid, status, steps_json = audit_case(
        request, identities, audit_log, rules_by_category, evidence_items, resource_user_map
    )
    print(f"Result: case_id={cid} status={status} steps_json_len={len(eval(steps_json)) if steps_json else 0}")
    
    # Parse steps_json to see what steps were generated
    import json
    try:
        steps = json.loads(steps_json)
        print(f"  Steps count: {len(steps)}")
        phases = [s.get("phase") for s in steps]
        print(f"  Phases: {phases}")
        # Show first few steps
        for s in steps[:5]:
            print(f"    step_no={s.get('step_no')} phase={s.get('phase')} sys={s.get('system_id')} res={s.get('resource_id')} op={s.get('operation')} state={s.get('state')} evid={s.get('evidence_id')}")
    except Exception as e:
        print(f"  Error parsing steps_json: {e}")
        print(f"  steps_json raw: {steps_json[:100] if steps_json else 'None'}...")
