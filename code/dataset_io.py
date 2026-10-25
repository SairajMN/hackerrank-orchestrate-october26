"""Data ingestion layer for the deletion-audit agent.

Reads all participant-facing CSV files and evidence artifacts from dataset/.
All paths are resolved relative to the repository root so the solution stays
portable across macOS, Linux and Windows.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")
EVIDENCE_DIR = os.path.join(DATASET_DIR, "evidence")


def read_csv(path: str) -> List[Dict[str, str]]:
    """Read a CSV file into a list of dicts (stripped, empty-safe)."""
    rows: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append({k: (v or "").strip() for k, v in row.items()})
    return rows


def load_deletion_requests(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


def load_user_identities(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


def load_user_audit_log(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


def load_system_activity(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


def load_deletion_rules(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


def load_evidence_manifest(path: str) -> List[Dict[str, str]]:
    return read_csv(path)


@dataclass
class EvidenceItem:
    file_id: str
    file_path: str
    origin: str
    captured_at: str
    kind: str  # sql, json, log, pdf, image, txt
    parsed: Any = None


def _parse_sql(path: str) -> Dict[str, List[Dict[str, str]]]:
    """Execute a SQLite-compatible SQL snapshot and return every table's rows."""
    conn = sqlite3.connect(":memory:")
    try:
        with open(path, encoding="utf-8") as fh:
            conn.executescript(fh.read())
        tables: Dict[str, List[Dict[str, str]]] = {}
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        for (table,) in cur.fetchall():
            cur2 = conn.execute(f"SELECT * FROM {table}")
            rows = cur2.fetchall()
            cols = [d[0] for d in cur2.description]
            tables[table] = [
                dict(zip(cols, [str(v) if v is not None else "" for v in r]))
                for r in rows
            ]
        return tables
    finally:
        conn.close()


def _parse_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _parse_log(path: str) -> List[Dict[str, str]]:
    """Parse a structured service log into one dict per line.

    Handles both resource_lookup_trace and service_events formats, including
    quoted values such as match_key="g.silva76.jr@gmail.com".
    """
    entries: List[Dict[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            entry: Dict[str, str] = {"raw": line}
            m = re.match(r"^(\S+)\s+level=(\S+)\s+(.*)$", line)
            if m:
                entry["timestamp"] = m.group(1)
                entry["level"] = m.group(2)
                rest = m.group(3)
                for kv in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', rest):
                    val = kv.group(2)
                    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
                        val = val[1:-1]
                    entry[kv.group(1)] = val
            entries.append(entry)
    return entries


def _parse_pdf(path: str) -> str:
    """Extract text from a PDF file using pypdf."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    try:
        reader = PdfReader(path)
        parts: List[str] = []
        for page in reader.pages:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            parts.append(t)
        return "\n".join(parts)
    except Exception:
        return ""


def _parse_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()



def parse_evidence_file(file_id: str, file_path: str, origin: str, captured_at: str) -> EvidenceItem:
    full_path = os.path.join(DATASET_DIR, file_path)
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".sql":
        kind = "sql"
        parsed = _parse_sql(full_path)
    elif ext == ".json":
        kind = "json"
        parsed = _parse_json(full_path)
    elif ext == ".log":
        kind = "log"
        parsed = _parse_log(full_path)
    elif ext in (".txt",):
        kind = "text"
        parsed = _parse_text(full_path)
    elif ext in (".pdf",):
        kind = "pdf"
        parsed = _parse_pdf(full_path)
    elif ext in (".png", ".jpg", ".jpeg"):
        kind = ext.lstrip(".")
        parsed = None
    else:
        kind = "unknown"
        parsed = None

    if not captured_at:
        captured_at = _captured_at_from_path(file_path)

    return EvidenceItem(
        file_id=file_id,
        file_path=file_path,
        origin=origin,
        captured_at=captured_at,
        kind=kind,
        parsed=parsed,
    )


def load_evidence_items(manifest: List[Dict[str, str]]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for row in manifest:
        items.append(
            parse_evidence_file(
                file_id=row["file_id"],
                file_path=row["file_path"],
                origin=row["origin"],
                captured_at=row.get("captured_at", ""),
            )
        )
    return items


@dataclass
class Indexes:
    identities: List[Dict[str, str]] = field(default_factory=list)
    identities_by_email: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    audit_log: List[Dict[str, str]] = field(default_factory=list)
    rules: List[Dict[str, str]] = field(default_factory=list)
    rules_by_category: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    evidence: List[EvidenceItem] = field(default_factory=list)
    evidence_by_id: Dict[str, EvidenceItem] = field(default_factory=dict)


def build_indexes(
    identities: List[Dict[str, str]],
    audit_log: List[Dict[str, str]],
    rules: List[Dict[str, str]],
    evidence: List[EvidenceItem],
) -> Indexes:
    idx = Indexes()
    idx.identities = identities
    for ident in identities:
        email = (ident.get("email") or "").strip().lower()
        if email:
            idx.identities_by_email.setdefault(email, []).append(ident)
    idx.audit_log = audit_log
    idx.rules = rules
    for rule in rules:
        idx.rules_by_category.setdefault(rule.get("data_category", ""), []).append(rule)
    idx.evidence = evidence
    for item in evidence:
        idx.evidence_by_id[item.file_id] = item
    return idx

