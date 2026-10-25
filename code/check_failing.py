#!/usr/bin/env python3
"""Check the three failing cases"""
import csv, json

with open('output.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['case_id'] in ['case_21', 'case_22', 'case_26']:
            with open('failing_detail.txt', 'w') as out:
                out.write(f"{row['case_id']}: {row['deletion_status']}\n")
                steps = json.loads(row['steps_json'])
                out.write(f"  steps count: {len(steps)}\n")
                for s in steps:
                    out.write(f"    step {s['step_no']}: {s['phase']} {s['system_id']} {s['resource_id']} {s['operation']} {s['state']}\n")
                out.write("\n")
            print(f"Wrote details for {row['case_id']}")