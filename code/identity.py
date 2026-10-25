"""Identity resolution: map a request email to current + historical identifiers."""

from __future__ import annotations

from typing import Dict, List, Set


def resolve_user_id(
    email: str,
    identities: List[Dict[str, str]],
    audit_log: List[Dict[str, str]],
) -> str:
    """Return the stable user_id for the request email, or '' if unknown."""
    email_l = (email or "").strip().lower()
    if not email_l:
        return ""

    # 1) direct match on current snapshot email
    for ident in identities:
        if (ident.get("email") or "").strip().lower() == email_l:
            return ident.get("user_id", "")

    # 2) match against historical email changes in the audit log
    for entry in audit_log:
        if entry.get("field_name") != "email":
            continue
        old_v = (entry.get("old_value") or "").strip().lower()
        new_v = (entry.get("new_value") or "").strip().lower()
        if old_v == email_l or new_v == email_l:
            return entry.get("user_id", "")

    return ""


def collect_identifiers(
    email: str,
    user_id: str,
    identities: List[Dict[str, str]],
    audit_log: List[Dict[str, str]],
) -> Dict[str, Set[str]]:
    """Gather every identifier that may still appear in downstream systems.

    Returns emails, phones, email_hashes and user_ids known for the subject.
    """
    emails: Set[str] = set()
    phones: Set[str] = set()
    email_hashes: Set[str] = set()
    user_ids: Set[str] = set()

    if email:
        emails.add(email.strip().lower())
    if user_id:
        user_ids.add(user_id.strip())

    # current snapshot row (may be a different email than the request email)
    for ident in identities:
        uid = (ident.get("user_id") or "").strip()
        if uid and (not user_id or uid == user_id):
            user_ids.add(uid)
            for key in ("email", "phone", "email_hash"):
                v = (ident.get(key) or "").strip()
                if key == "email" and v:
                    emails.add(v.lower())
                elif key == "phone" and v:
                    phones.add(v)
                elif key == "email_hash" and v:
                    email_hashes.add(v.lower())

    # historical audit-log changes for this user
    target_users = user_ids if user_ids else {user_id}
    for entry in audit_log:
        uid = (entry.get("user_id") or "").strip()
        if uid and uid not in target_users:
            continue
        field_name = entry.get("field_name") or ""
        old_v = (entry.get("old_value") or "").strip()
        new_v = (entry.get("new_value") or "").strip()
        if field_name == "email":
            if old_v:
                emails.add(old_v.lower())
            if new_v:
                emails.add(new_v.lower())
        elif field_name == "phone":
            if old_v:
                phones.add(old_v)
            if new_v:
                phones.add(new_v)
        elif field_name == "email_hash":
            if old_v:
                email_hashes.add(old_v.lower())
            if new_v:
                email_hashes.add(new_v.lower())
        if uid:
            user_ids.add(uid)

    return {
        "emails": emails,
        "phones": phones,
        "email_hashes": email_hashes,
        "user_ids": user_ids,
    }
