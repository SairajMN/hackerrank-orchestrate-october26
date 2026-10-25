"""Validate agent logic against the 32 sample cases with known outputs."""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import audit_case
from evidence import _build_resource_user_map
from dataset_io import (
    load_deletion_requests,
    load_deletion_rules,
    load_evidence_items,
    load_evidence_manifest,
    load_user_audit_log,
    load_user_identities,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")


def main():
    identities = load_user_identities(os.path.join(DATASET_DIR, "user_identities.csv"))
    audit_log = load_user_audit_log(os.path.join(DATASET_DIR, "user_audit_log.csv"))
    rules = load_deletion_rules(os.path.join(DATASET_DIR, "deletion_rules.csv"))
    manifest = load_evidence_manifest(os.path.join(DATASET_DIR, "evidence_files.csv"))
    evidence_items = load_evidence_items(manifest)
    requests = load_deletion_requests(os.path.join(DATASET_DIR, "sample_deletion_requests.csv"))

    # Build rules_by_category for audit_case
    rules_by_category = {}
    for rule in rules:
        rules_by_category.setdefault(rule.get("data_category", ""), []).append(rule)

    class _Idx:
        pass
    _all_idx = _Idx()
    _all_idx.evidence = evidence_items
    resource_user_map = _build_resource_user_map(_all_idx)

    expected = {}
    with open(os.path.join(DATASET_DIR, "sample_output.csv"), newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            expected[row["case_id"]] = row

    results = {}
    for request in requests:
        case_id, status, steps_json = audit_case(
            request, identities, audit_log, rules_by_category, evidence_items,
            resource_user_map,
        )
        results[case_id] = (status, steps_json)

    total = len(requests)
    status_ok = 0
    mismatches = []
    for case_id, (status, steps_json) in results.items():
        exp = expected.get(case_id)
        if not exp:
            print(f"{case_id}: NO EXPECTED OUTPUT")
            continue
        if status == exp["deletion_status"]:
            status_ok += 1
        else:
            mismatches.append((case_id, status, exp["deletion_status"]))

    print(f"\nSample status accuracy: {status_ok}/{total}")
    if mismatches:
        print("Mismatches:")
        for case_id, got, exp in mismatches:
            print(f"  {case_id}: got={got} exp={exp}")


if __name__ == "__main__":
    main()

