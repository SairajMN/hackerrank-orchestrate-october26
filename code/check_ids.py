import sys
sys.path.insert(0, "/Users/sahil/Desktop/HACKATHON/hackerrank-orchestrate-october26/code")
from code.dataset_io import load_deletion_requests
requests = load_deletion_requests("dataset/deletion_requests.csv")
print(f"Total requests: {len(requests)}")
print(f"First 5: {[(r['case_id'], r.get('email','')[:20]) for r in requests[:5]]}")
print(f"Last 5: {[(r['case_id'], r.get('email','')[:20]) for r in requests[-5:]]}")
case_ids = [r['case_id'] for r in requests]
print(f"Min case_id: {min(case_ids)}")
print(f"Max case_id: {max(case_ids)}")