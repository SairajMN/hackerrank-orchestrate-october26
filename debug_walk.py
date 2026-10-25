import sys, os, json
sys.path.insert(0, "code")
from code.evidence import find_user_records_by_id, _matches_identifier, _row_matches, _norm
from code.dataset_io import load_deletion_requests, load_user_identities, load_user_audit_log, load_deletion_rules, load_evidence_manifest, load_evidence_items, build_indexes
from code.identity import resolve_user_id, collect_identifiers

requests = load_deletion_requests("dataset/sample_deletion_requests.csv")
identities = load_user_identities("dataset/user_identities.csv")
audit_log = load_user_audit_log("dataset/user_audit_log.csv")
rules = load_deletion_rules("dataset/deletion_rules.csv")
manifest = load_evidence_manifest("dataset/evidence_files.csv")
evidence_items = load_evidence_items(manifest)
idx = build_indexes(identities, audit_log, rules, evidence_items)

req = [r for r in requests if r["case_id"]=="case_21"][0]
print("Request email:", req.get("email"))
print("Audit at:", req.get("audit_at"))

user_id = resolve_user_id(req.get("email", ""), identities, audit_log)
ids = collect_identifiers(req.get("email", ""), user_id, identities, audit_log)
print("Identifiers:", ids)
print("  emails:", ids["emails"])
print("  phones:", ids["phones"])
print("  email_hashes:", ids["email_hashes"])
print("  user_ids:", ids["user_ids"])

# Check if amara-okeke@proton.me matches any identifier
for key in ids:
    print(f"  ids['{key}'] = {ids[key]}")

# Now find records
records = find_user_records_by_id(evidence_items, ids, req.get("audit_at", ""), idx.resource_user_map)
print(f"\nFound {len(records)} records")
for r in records:
    print(f"  {r.file_id if hasattr(r, 'file_id') else '?'}: data_category={r.data_category}, state={r.state}, resource_id={r.resource_id}, captured_at={r.captured_at}")

# Now let's manually check evidence_92
print("\n=== Manual check of evidence_92 ===")
for item in evidence_items:
    if hasattr(item, 'file_id') and item.file_id == "evidence_92":
        print(f"evidence_92: kind={item.kind}")
        if item.parsed:
            for table, rows in item.parsed.items():
                if table != "snapshot_scope" and rows:
                    print(f"  Table {table}: {len(rows)} rows")
                    for row in rows[:5]:
                        merged = _merge_json_columns(row)
                        rid = _norm(merged.get("resource_id"))
                        print(f"    resource_id={rid}")
                        # Check matching
                        for key in ("email", "phone", "email_hash", "customer_reference", "subject_reference"):
                            val = _norm(merged.get(key, ""))
                            if val:
                                match = _matches_identifier(val, ids)
                                print(f"      {key}={val} -> match={match}")
                        # Also check _row_matches
                        row_match = _row_matches(merged, ids)
                        print(f"      _row_matches={row_match}")

def _merge_json_columns(row):
    merged = {}
    for key, val in row.items():
        if isinstance(val, str) and val.startswith("{"):
            try:
                obj = json.loads(val)
            except Exception:
                continue
            if isinstance(obj, dict):
                for k, v in obj.items():
                    merged[k] = "" if v is None else str(v)
        else:
            merged[key] = "" if val is None else str(val)
    return merged