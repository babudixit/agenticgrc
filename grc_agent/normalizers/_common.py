"""Shared helpers for vendor finding normalizers.

Normalizers reshape vendor payloads into `UnifiedFinding` only — they never
infer NIST/ATT&CK mappings. Severity maps and export-file loaders live here so
Qualys / SIEM / CSPM / (later) other adapters stay consistent without
duplicating FR-205/FR-208 behavior.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from grc_agent.schemas import Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "5": Severity.CRITICAL,
    "4": Severity.HIGH,
    "high": Severity.HIGH,
    "3": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "2": Severity.LOW,
    "low": Severity.LOW,
    "1": Severity.INFORMATIONAL,
    "0": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def normalize_severity(raw: Any, *, vendor: str) -> Severity:
    """Map a vendor severity (string or int-like) onto the canonical Severity enum."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise ValueError(f"{vendor} finding is missing severity")
    key = str(raw).strip().lower()
    try:
        return _SEVERITY_MAP[key]
    except KeyError:
        raise ValueError(
            f"Unrecognized {vendor} severity: {raw!r} "
            f"(expected one of {sorted(set(_SEVERITY_MAP))})"
        ) from None


def first_nonempty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def as_str_list(value: Any) -> list[str]:
    """Coerce vendor list / comma-string / single-string fields into a clean str list."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if "," in text or ";" in text:
            return [part.strip() for part in re.split(r"[,;]+", text) if part.strip()]
        return [text]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def extract_cves(*values: Any) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in as_str_list(value):
            for match in _CVE_RE.findall(item):
                cve = match.upper()
                if cve not in seen:
                    seen.add(cve)
                    found.append(cve)
    return found


def extract_cwes(*values: Any) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in as_str_list(value):
            for match in _CWE_RE.findall(item):
                cwe = match.upper()
                if cwe not in seen:
                    seen.add(cwe)
                    found.append(cwe)
    return found


def extract_techniques(*values: Any) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in as_str_list(value):
            for match in _TECHNIQUE_RE.findall(item):
                tech = match.upper()
                if tech not in seen:
                    seen.add(tech)
                    found.append(tech)
    return found


def read_json_records(
    path: Path,
    *,
    vendor: str,
    list_keys: Iterable[str] = ("findings", "alerts", "results", "detections", "items"),
) -> list[dict[str, Any]]:
    """Load a vendor export: bare JSON array or an object wrapping a records list."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in list_keys:
            if key in data and isinstance(data[key], list):
                return list(data[key])
    raise ValueError(
        f"Unrecognized {vendor} export format in {path}: expected a JSON array or an "
        f"object with one of {list(list_keys)}."
    )
