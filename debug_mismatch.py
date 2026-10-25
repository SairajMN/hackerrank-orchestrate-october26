from dataset_io import *
from identity import resolve_user_id, collect_identifiers

identities = load_user_identities('dataset/user_identities.csv')
audit_log = load_user_audit_log('dataset/user_audit_log.csv')
requests = load_deletion_requests('dataset/sample_deletion_requests.csv')

# Find case_07
for r in requests:
    if r['case_id'] == 'case_07':
        email = r['email']
        audit_at = r['audit_at']
        print(f'case_07 email={email} audit_at={audit_at}')
        user_id = resolve_user_id(email, identities, audit_log)
        print(f'user_id={user_id}')
        ids = collect_identifiers(email, user_id, identities, audit_log)
        print(f'emails={ids["emails"]}')
        print(f'phones={ids["phones"]}')
        print(f'email_hashes={ids["email_hashes"]}')
        print(f'user_ids={ids["user_ids"]}')
        break